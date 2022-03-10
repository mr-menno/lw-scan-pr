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

  let message = `
<h1>Lacework Scanner</h1>
<p>
  Scanned image <strong>${results.cve.image.image_info.registry}/${results.cve.image.image_info.repository}:${results.cve.image.image_info.tags.join(',')}</strong><br />
  Image digest <strong>${results.cve.image.image_info.image_digest}</strong>
</p>

<h2>Vulnerability Summary<h2>
<table>
  <tr><th>Severity</th><th>Count</th><th>Fixable</th></tr>
  <tr><td>Critical</td><td>${vulnCount.critical.found}</td><td>${vulnCount.critical.fixable})</td></tr>
  <tr><td>High</td><td>${vulnCount.high.found}</td><td>${vulnCount.high.fixable})</td></tr>
  <tr><td>Medium</td><td>${vulnCount.medium.found}</td><td>${vulnCount.medium.fixable})</td></tr>
  <tr><td>Low</td><td>${vulnCount.low.found}</td><td>${vulnCount.low.fixable})</td></tr>
  <tr><td>Info</td><td>${vulnCount.info.found}</td><td>${vulnCount.info.fixable})</td></tr>
</table>
  `;

  message += `<h2>Lacework Policies</h2>`;
  if(policies_violated.length>0) {
    message += `
    <details>
    <summary>Lacework policies have been violated</summary>
    `;
    policies_violated.forEach(p=> {
      message+=`<p><strong>${p.Policy.policy_type} - ${p.Policy.policy_name}</strong><br />`;
      message+=`${p.Policy.description}</p>`;
    })
    message += `</details>`
  } else {
    message += '<p>all policies have passed</p>'
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