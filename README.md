# DefectDojo
DefectDojo is a security tool that automates application security vulnerability management. DefectDojo streamlines the application security testing process by offering features such as importing third party security findings, merging and de-duping, integration with Jira, templating, report generation and security metrics.

## Build DefectDojo
### Docker locally
```
make build
```



## TRY convert parser
### Install node and packages
```
cd DefectDojoReportConverter
npm install json2csv --save
npm install xml2js --save
```

```
node convert_webinspect_xml_to_generic_defectdojo_csv.js webInspectResult.xml > webInspectResultDefecDojoGeneric.csv
```

### on docker
```
make convert
```
