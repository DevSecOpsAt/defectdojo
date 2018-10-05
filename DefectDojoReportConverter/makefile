update:
	npm install
build:
	docker build --no-cache=true -t if08017/convert-wi2dd:latest .
download:
	curl -X GET --header 'Accept: text/xml' 'http://${SERVER_IP}:8083/webinspect/scanner/scans/${SCAN_ID}.xml?detailType=vulnerabilities' > ./results/${JOB_NAME}-${BUILD_NUMBER}.xml
convert:
	docker run --rm -v `pwd`:/vapt if08017/convert-wi2dd:latest node /vapt_home/convert_webinspect_xml_to_generic_defectdojo_csv.js /vapt/results/${JOB_NAME}-${BUILD_NUMBER}.xml > ./results/${JOB_NAME}.csv
post:
	docker run --rm -v `pwd`:/vapt postman/newman_ubuntu1404:latest run /vapt/vapt.postman_collection.json -g /vapt/vapt.postman_environment.json -k --global-var vapt_date=${BUILD_TIMESTAMP} --global-var vapt_file=/vapt/results/${JOB_NAME}.csv --global-var vapt_engagement=${VAPT_ENGAGEMENT}

d:
	curl -X GET --header 'Accept: text/xml' 'http://10.1.65.79:8083/webinspect/scanner/scans/85898606-0c89-4360-a725-c9fe00b78303.xml?detailType=vulnerabilities' > ./results/JOB_NAME-BUILD_NUMBER.xml
c:
	docker run --rm -v `pwd`:/vapt if08017/convert-wi2dd:latest node /vapt/convert_webinspect_xml_to_generic_defectdojo_csv.js /vapt/results/JOB_NAME-BUILD_NUMBER.xml > ./results/JOB_NAME.csv
p:
	docker run --rm -v `pwd`:/vapt postman/newman_ubuntu1404:latest run /vapt/vapt.postman_collection.json -g /vapt/vapt.postman_environment.json -k -x --global-var vapt_date=2018-10-01 --global-var vapt_file=/vapt/results/JOB_NAME.csv --global-var vapt_engagement=/api/v1/engagements/1/
