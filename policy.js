const fs = require('fs');

let policy = {};

var walk = function(dir) {
  var results = [];
  try {
    var list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = dir + '/' + file;
        var stat = fs.statSync(file);
        if (stat && stat.isDirectory()) { 
            /* Recurse into a subdirectory */
            results = results.concat(walk(file));
        } else { 
            /* Is a file */
            results.push(file);
        }
    });
  } catch(e) {}
  return results;
}

function findEvaluationJson() {
  let files = walk('./lw-scanner-data');
  return files.find(f=>f.match(/evaluation.*\.json/))
}

function santizeTableCell(text) {
  return text.replace('|','')
    .replace("\n","<br />");
}

policy.result = ({github,context,fail_policy,fail_threshold}) => {
  let resultsjson = findEvaluationJson();
  let result_code = 0;

  if(!resultsjson) {
    console.error("Error: Scan results NOT found");
    return {
      message: "LW Scanner did not generate a JSON results file",
      code: 1
    };
  }
  console.log("Scan Results JSON",resultsjson);
  let file = fs.readFileSync(resultsjson);
  let results = JSON.parse(file);
  results.policy = results.policy || [];
  let policies_violated = (results.policy||[]).filter(p=>p.status=='VIOLATED');
  console.log(JSON.stringify(results,null,2));

  //---- VULN COUNT
  let vulnCount = {
    critical: {found:0, fixable:0},
    high: {found:0, fixable:0},
    medium: {found:0, fixable:0},
    low: {found:0, fixable:0},
    info: {found:0, fixable:0}
  }
  let vulnFixable = [];
  results.cve.image.image_layers.filter(l=>l.packages.length>0).forEach(layer => {
    layer.packages.forEach(package => {
      package.vulnerabilities.forEach(vulnerability => {
        if(vulnerability.status=='VULNERABLE') {
          vulnCount[vulnerability.severity.toLowerCase()].found++;
          if(vulnerability.fix_version) { 
            vulnCount[vulnerability.severity.toLowerCase()].fixable++;
            vulnFixable.push(vulnerability);
          }
        }
      })
    })
  });

  vuln_fail_reason="";
  if(fail_threshold==="critical-fixable" && vulnCount.critical.fixable>0) {
    result_code=51;
    vuln_fail_reason="Warning: failing due to critical AND fixable vulnerabilities";
  } if(fail_threshold==="critical" && vulnCount.critical.fixable>0) {
    result_code=50;
    vuln_fail_reason="Warning: failing due to critical vulnerabilities";
  } if(fail_threshold==="high-fixable" && vulnCount.critical.fixable>0) {
    result_code=41;
    vuln_fail_reason="Warning: failing due to high AND fixable vulnerabilities";
  } if(fail_threshold==="high" && vulnCount.critical.fixable>0) {
    result_code=40;
    vuln_fail_reason="Warning: failing due to high vulnerabilities";
  } if(fail_threshold==="medium-fixable" && vulnCount.critical.fixable>0) {
    result_code=31;
    vuln_fail_reason="Warning: failing due to medium AND fixable vulnerabilities";
  } if(fail_threshold==="medium" && vulnCount.critical.fixable>0) {
    result_code=30;
    vuln_fail_reason="Warning: failing due to medium vulnerabilities";
  } if(fail_threshold==="low-fixable" && vulnCount.critical.fixable>0) {
    result_code=21;
    vuln_fail_reason="Warning: failing due to low AND fixable vulnerabilities";
  } if(fail_threshold==="low" && vulnCount.critical.fixable>0) {
    result_code=20;
    vuln_fail_reason="Warning: failing due to low vulnerabilities";
  } if(fail_threshold==="info-fixable" && vulnCount.critical.fixable>0) {
    result_code=10;
    vuln_fail_reason="Warning: failing due to info AND fixable vulnerabilities";
  } if(fail_threshold==="info" && vulnCount.critical.fixable>0) {
    result_code=11;
    vuln_fail_reason="Warning: failing due to critical vulnerabilities";
  } else {
    console.log("vulnerability threshold not configured")
  }

  let message = `
# Lacework Scanner

Scanned image **${results.cve.image.image_info.repository}:${results.cve.image.image_info.tags.join(',')}**

## Vulnerability Summary

${vuln_fail_reason}

| Severity | Count | Fixable |
| --- | --- | --- |
| Critical | ${vulnCount.critical.found} | ${vulnCount.critical.fixable} |
| High | ${vulnCount.high.found} | ${vulnCount.high.fixable} |
| Medium | ${vulnCount.medium.found} | ${vulnCount.medium.fixable} |
| Low | ${vulnCount.low.found} | ${vulnCount.low.fixable} |
| Info | ${vulnCount.info.found} | ${vulnCount.info.fixable} |

`;

  if(vulnFixable.length>0) {
    message += `## Fixable Vulnerabilities\n`;
    message += "<details><summary>Fixable vulnerabilities have been found</summary>\n\n"
    message += '| Severity | CVE | Description | Fix Version |\n';
    message += '| -------- | --- | ----------- | ----------- |\n';
    vulnFixable.filter(v=>v.severity=='Critical')
      .forEach(vuln => message+=`| ${vuln.severity} | ${vuln.name} | ${santizeTableCell(vuln.description)} | ${vuln.fix_version} |\n`);
    vulnFixable.filter(v=>v.severity=='High')
      .forEach(vuln => message+=`| ${vuln.severity} | ${vuln.name} | ${santizeTableCell(vuln.description)} | ${vuln.fix_version} |\n`);
    vulnFixable.filter(v=>v.severity=='Medium')
      .forEach(vuln => message+=`| ${vuln.severity} | ${vuln.name} | ${santizeTableCell(vuln.description)} | ${vuln.fix_version} |\n`);
    vulnFixable.filter(v=>v.severity=='Low')
      .forEach(vuln => message+=`| ${vuln.severity} | ${vuln.name} | ${santizeTableCell(vuln.description)} | ${vuln.fix_version} |\n`);
    vulnFixable.filter(v=>v.severity=='Info')
      .forEach(vuln => message+=`| ${vuln.severity} | ${vuln.name} | ${santizeTableCell(vuln.description)} | ${vuln.fix_version} |\n`);
    message += '</details>\n\n';
  }

  message += `## Lacework Policies\n`;
  fail_policy = fail_policy==="true"?true:false;
  if(policies_violated.length>0) {
    message += `<details><summary>Lacework policies have been violated ${fail_policy?"(failing scan results due to policy)":""}</summary>\n\n`;
    message += '| Policy | Details |\n';
    message += '| --- | --- |\n';
    policies_violated.forEach(p=> {
      message+=`| **${p.Policy.policy_type} - ${p.Policy.policy_name} ** | ${p.Policy.description} |\n`;
    })
    message += "\n";
    message += `</details>`
    if(fail_policy) {
      console.warn("Warning: failing due to policy violations")
      policies_violated.forEach(policy => {
        console.warn(`${p.Policy.policy_type} - ${p.Policy.policy_name}`)
      })
      result_code=2;
    }
  } else if (results.policy.length<1) { 
    message += 'No Scanning Policies have been attached\n'
  } else {
    //REMOVE THIS
    message += 'All policies have passed\n'+JSON.stringify(result.policy,null,2)
  }
  return {
    message: message,
    code: result_code,
    vuln_fail_reason
  };
}

module.exports = policy;