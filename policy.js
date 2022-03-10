const fs = require('fs');

let policy = {};

policy.result = (github) => {
  let file = fs.readFileSync('lw-scan-result.json');
  let results = JSON.parse(file);
  let policies_violated = results.policy.filter(p=>p.status=='VIOLATED');

  //---- VULN COUNT
  let vulnCount = {
    critical: {found:0, fixable:0},
    high: {found:0, fixable:0},
    medium: {found:0, fixable:0},
    low: {found:0, fixable:0},
    info: {found:0, fixable:0}
  }
  results.cve.image.image_layers.filter(l=>l.packages.length>0).forEach(layer => {
    layer.packages.forEach(package => {
      package.vulnerabilities.forEach(vulnerability => {
        console.log(vulnerability);
        if(vulnerability.status=='VULNERABLE') {
          vulnCount[vulnerability.severity.toLowerCase()].found++;
          if(vulnerability.fix_version) vulnCount[vulnerability.severity.toLowerCase()].fixable++;
        }
      })
    })
  });

  let message = `Scanned image *${results.cve.image.image_info.registry}/${results.cve.image.image_info.repository}:${results.cve.image.image_info.tags.join(',')}
  image digest: ${results.cve.image.image_info.image_digest}
  ---
  Vulnerability Summary:
  Critical(fixable): ${vulnCount.critical.found}(${vulnCount.critical.fixable})
  High(fixable):     ${vulnCount.high.found}(${vulnCount.high.fixable})
  Medium(fixable):   ${vulnCount.medium.found}(${vulnCount.medium.fixable})
  Low(fixable):      ${vulnCount.low.found}(${vulnCount.low.fixable})
  Info(fixable):     ${vulnCount.info.found}(${vulnCount.info.fixable})
  --
  `;

  if(policies_violated.length>0) {
    message += `
    <details>
    <summary>Lacework policies have been violated</summary>
    `;
    policies_violated.forEach(p=> {
      message+=`
      *${p.Policy.policy_type} - ${p.Policy.policy_name}*<br />
      ${p.Policy.description}
      `
    })
    message += `</details>`
  }
  console.log(message);
  return message;
}

module.exports = policy;

/*

          const fs = require('fs');
          let file = fs.readFileSync('lw-scan-result.json');
          console.log(file);
          let results = JSON.parse(file);
          console.log(results);
          await github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: 'Welcome, new contributor!'
          })
*/