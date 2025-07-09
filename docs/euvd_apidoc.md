# ENISA EUVD Endpoints
Source: https://euvd.enisa.europa.eu/apidoc

## Show latest vulnerabilities
Endpoint: /api/lastvulnerabilities
Method: GET
Authentication: No authentication required
Request Headers: No custom headers
Request Body: Not applicable
Response Size Limit: Maximum 8 records
Curl Example:
curl -X GET https://euvdservices.enisa.europa.eu/api/lastvulnerabilities
HTTP Request:
GET https://euvdservices.enisa.europa.eu/api/lastvulnerabilities HTTP/1.1


## Show latest exploited vulnerabilities
Endpoint: /api/exploitedvulnerabilities
Method: GET
Authentication: No authentication required
Request Headers: No custom headers
Request Body: Not applicable
Response Size Limit: Maximum 8 records
Curl Example:
curl -X GET https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities
HTTP Request:
GET https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities HTTP/1.1

## Show latest critical vulnerabilities
Endpoint: /api/criticalvulnerabilities
Method: GET
Authentication: No authentication required
Request Headers: No custom headers
Request Body: Not applicable
Response Size Limit: Maximum 8 records
Curl Example:
curl -X GET https://euvdservices.enisa.europa.eu/api/criticalvulnerabilities
HTTP Request:
GET https://euvdservices.enisa.europa.eu/api/criticalvulnerabilities HTTP/1.1

## Scores & Filters
### Query Vulnerabilities with Flexible Filters
Endpoint: /api/search
Method: GET
Authentication: No authentication required
Request Headers: No custom headers
Request Body: Not applicable
Response Size Limit: Maximum 100 records per request
Parameters:
```
fromScore (0-10, e.g., fromScore=7.5)
toScore (0-10, e.g., toScore=10)
fromEpss (0-100, e.g., fromEpss=20)
toEpss (0-100, e.g., toEpss=90)
fromDate (YYYY-MM-DD, e.g., fromDate=2023-01-14)
toDate (YYYY-MM-DD, e.g., toDate=2025-01-14)
product (string, e.g., product=Windows)
vendor (string, e.g., vendor=Microsoft)
assigner (string, e.g., assigner=mitre)
exploited (true/false, e.g., exploited=true)
page (integer, starts at 0, e.g., page=2)
text (keywords, e.g., text=vulnerability)
size (integer, default 10, e.g., size=100 (max))
```

Curl Example:
curl -X GET https://euvdservices.enisa.europa.eu/api/search?fromScore=0&toScore=10
HTTP Request:
GET https://euvdservices.enisa.europa.eu/api/search?fromScore=0&toScore=10 HTTP/1.1

## Specific Resources
### Show EUVD by ID
Endpoint: /api/enisaid
Method: GET
Authentication: No authentication required
Request Headers: No custom headers
Request Body: Not applicable
Parameters:
id (string, e.g., id=EUVD-2025-4893)
Curl Example:
curl -X GET https://euvdservices.enisa.europa.eu/api/enisaid?id=EUVD-2024-45012
HTTP Request:
GET https://euvdservices.enisa.europa.eu/api/enisaid?id=EUVD-2024-45012 HTTP/1.1

### Show advisory by ID
Endpoint: /api/advisory
Method: GET
Authentication: No authentication required
Request Headers: No custom headers
Request Body: Not applicable
Parameters:
id (string, e.g., id=oxas-adv-2024-0002)
Curl Example:
curl -X GET https://euvdservices.enisa.europa.eu/api/advisory?id=cisco-sa-ata19x-multi-RDTEqRsy
HTTP Request:
GET https://euvdservices.enisa.europa.eu/api/advisory?id=cisco-sa-ata19x-multi-RDTEqRsy HTTP/1.1