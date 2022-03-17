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
  console.log(JSON.stringify(context,null,2))
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

  let message = `
# Lacework Scanner

Scanned image **${results.cve.image.image_info.repository}:${results.cve.image.image_info.tags.join(',')}**

## Vulnerability Summary
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
    if(fail_policy) result_code=2;
  } else if (results.policy.length<1) { 
    message += 'No Scanning Policies have been attached\n'
  } else {
    message += 'All policies have passed\n'
  }
  return {
    message: message,
    code: 0
  };
}

module.exports = policy;