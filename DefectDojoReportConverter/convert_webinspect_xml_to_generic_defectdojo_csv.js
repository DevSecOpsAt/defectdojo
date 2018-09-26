var fs = require('fs');
if (process.argv.length <= 2) {
    console.log("Usage: " + __filename + " SOME_PARAM");
    process.exit(-1);
}
const webInspectReport = fs.readFileSync(process.argv[2], 'UTF-8');
const Json2csvParser = require('json2csv').Parser;
var parseString = require('xml2js').parseString;

function severityMapping(severity){
    let mapping = {
      0: "Informational",
      1: "Low",
      2: "Medium",
      3: "High",
      4: "Critical"
    };
     return mapping[severity];
  }

parseString(webInspectReport, function (err, result) {
    const fields = ['Date', 'Title', 'CweId', 'Url', 'Severity', 'Description', 'Mitigation', 'Impact', 'References', 'Active', 'Verified'];
    const parsedResult = [];

    let date = result.Scan.StartTime[0].split(' ')[0];
    let Issues = result.Scan.Issues[0].Issue.map(issue =>{
        let result = {Date: "", Title: "", CweId: "", Url: "", Severity: "", Description: "", Mitigation: "", Impact: "", References: "", Active: "TRUE", Verified: "FALSE"}
        result.Date = date;
        result.Title = issue.Name[0];
        result.CweId = issue.SectionText;
        result.Url = issue.URL[0];
        result.Severity = severityMapping(issue.Severity.toString());
        let reportSections = issue.ReportSection.map(reportSection => {
            // console.log(reportSection)
            if (reportSection.Name[0] == "Reference Info"){
              if(reportSection.SectionText[0].split(' ')[2] == '/><b>CWE'){
                result.CweId = reportSection.SectionText[0].split(' ')[3];
              }
            }
            if (reportSection.Name[0] == "Summary"){
                result.Description = reportSection.SectionText[0].split(' ')[1];
            }
            if (reportSection.Name[0] == "Fix"){
                result.Mitigation = reportSection.SectionText[0];
            }
            if (reportSection.Name[0] == "Implication"){
                result.Impact = reportSection.SectionText[0];
            }
            if (reportSection.Name[0] == "Reference Info"){
                result.References = reportSection.SectionText[0];
            }
        });
        parsedResult.push(result);
    });

    const json2csvParser = new Json2csvParser({ fields });
    const csv = json2csvParser.parse(parsedResult);
    console.log(csv);
});
