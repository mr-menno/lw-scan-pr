const fs = require('fs');

// ---- supporting functions ----

// function to walk a directory tree
function walkDir(dir) {
  var results = [];
  try {
    var list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = dir + '/' + file;
        var stat = fs.statSync(file);
        if (stat && stat.isDirectory()) { 
            /* Recurse into a subdirectory */
            results = results.concat(walkDir(file));
        } else { 
            /* Is a file */
            results.push(file);
        }
    });
  } catch(e) {}
  return results;
}

// walk the tree and find the evaluation*.json file
function findEvaluationJson() {
  let files = walkDir('./lw-scanner-data');
  return files.find(f=>f.match(/evaluation.*\.json/))
}

// function to clean stray values from the table cells such as newlines.
function santizeTableCell(text) {
  return text.replace('|','')
    .replace("\n","<br />");
}

// ---- policy module ----
let LwScanAnalyzer = {};

// analyze results
LwScanAnalyzer.result = ({github,context,fail_policy,fail_severity,blocking}) => {
  //get scan results evaluation json file
  let resultsjson = findEvaluationJson();
  
  //set initial result code
  let result_code = 0;

  //error if scan results were not found
  if(!resultsjson) {
    console.error("Error: Scan results NOT found");
    return {
      message: "LW Scanner did not generate a JSON results file",
      code: 1
    };
  }

  // read evaluation.json for scan results
  console.log("Scan Results JSON",resultsjson);
  let file = fs.readFileSync(resultsjson);
  let results = JSON.parse(file);
  results.policy = results.policy || [];
  let policies_violated = (results.policy||[]).filter(p=>p.status=='VIOLATED');

  // count all found and fixable vulnerabilities
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

  // determine if a vulnerability should cause a failure
  vuln_fail_reason="";
  console.log("Analyzing vulns for fail severity threshold:",fail_severity,JSON.stringify(vulnCount,null,2));
  if(fail_severity==="critical-fixable" && vulnCount.critical.fixable>0) {
    result_code=51;
    vuln_fail_reason="Warning: failing due to critical AND fixable vulnerabilities";
  } else if(fail_severity==="critical" && vulnCount.critical.fixable>0) {
    result_code=50;
    vuln_fail_reason="Warning: failing due to critical vulnerabilities";
  } else if(fail_severity==="high-fixable" && vulnCount.high.fixable>0) {
    result_code=41;
    vuln_fail_reason="Warning: failing due to high AND fixable vulnerabilities";
  } else if(fail_severity==="high" && vulnCount.high.fixable>0) {
    result_code=40;
    vuln_fail_reason="Warning: failing due to high vulnerabilities";
  } else if(fail_severity==="medium-fixable" && vulnCount.medium.fixable>0) {
    result_code=31;
    vuln_fail_reason="Warning: failing due to medium AND fixable vulnerabilities";
  } else if(fail_severity==="medium" && vulnCount.medium.fixable>0) {
    result_code=30;
    vuln_fail_reason="Warning: failing due to medium vulnerabilities";
  } else if(fail_severity==="low-fixable" && vulnCount.low.fixable>0) {
    result_code=21;
    vuln_fail_reason="Warning: failing due to low AND fixable vulnerabilities";
  } else if(fail_severity==="low" && vulnCount.low.fixable>0) {
    result_code=20;
    vuln_fail_reason="Warning: failing due to low vulnerabilities";
  } else if(fail_severity==="info-fixable" && vulnCount.info.fixable>0) {
    result_code=10;
    vuln_fail_reason="Warning: failing due to info AND fixable vulnerabilities";
  } else if(fail_severity==="info" && vulnCount.info.fixable>0) {
    result_code=11;
    vuln_fail_reason="Warning: failing due to critical vulnerabilities";
  } else {
    console.log("vulnerability threshold not met")
  }
  if(vuln_fail_reason) console.warn("Warning: "+vuln_fail_reason)

  // Generate vulnerabilities details message  
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

  // Analyze Policies and Generate Policy Message
  message += `## Lacework Policies\n`;
  fail_policy = fail_policy==="true"?true:false;
  if(policies_violated.length>0) {
    message += `<details><summary>Lacework policies have been violated ${fail_policy?"(failing scan results due to policy)":""}</summary>\n\n`;
    message += '| Policy | Details |\n';
    message += '| --- | --- |\n';
    policies_violated.forEach(policy=> {
      message+=`| **${policy.Policy.policy_type} - ${policy.Policy.policy_name} ** | ${policy.Policy.description} |\n`;
    })
    message += "\n";
    message += `</details>`
    if(fail_policy) {
      // If FAIL_POLCY==true and violated policies have been found
      console.warn("Warning: failing due to policy violations")
      policies_violated.forEach(policy => {
        console.warn(`${policy.Policy.policy_type} - ${policy.Policy.policy_name}`)
      })
      result_code=2;
    }
  } else if (results.policy.length<1) { 
    message += 'No Scanning Policies have been attached\n'
  }

  return {
    message,
    code: blocking?result_code:0, //don't block if disabled
    vuln_fail_reason
  };
}

module.exports = LwScanAnalyzer;