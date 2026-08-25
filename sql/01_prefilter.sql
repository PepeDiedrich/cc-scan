-- Stage 1: cheap, high-recall scan of the Common Crawl URL Index.
-- A URL is endpoint evidence, never proof of a CVE or exposure.
COPY (
WITH source AS (
  SELECT url_host_registered_domain AS registered_domain, url_host_name AS host,
    url AS source_url, coalesce(url_path, '/') AS url_path,
    coalesce(url_query, '') AS source_query,
    fetch_status, fetch_time, content_mime_type, content_languages,
    warc_filename, warc_record_offset, warc_record_length
  FROM read_parquet([__PARQUET_PATHS__], union_by_name=true)
  WHERE subset = 'warc'
    AND fetch_status IN (200,201,204,301,302,307,308,400,401,403,404,405,406,
                         409,415,422,429,500,501,502,503)
), normalized AS (
  SELECT * EXCLUDE (source_url, source_query),
    CASE WHEN source_query = '' THEN source_url ELSE regexp_replace(source_url, '\?.*$', '') || '?' ||
      regexp_replace(source_query, '((token|key|secret|password|passwd|signature|auth|session)[^=&]*=)[^&]*', '\1<redacted>', 'gi') END AS url,
    regexp_replace(source_query, '((token|key|secret|password|passwd|signature|auth|session)[^=&]*=)[^&]*', '\1<redacted>', 'gi') AS url_query,
    lower(regexp_replace(url_path, '/+', '/', 'g')) AS normalized_path,
    lower(trim(regexp_replace(source_query, '((token|key|secret|password|passwd|signature|auth|session)[^=&]*=)[^&]*', '\1<redacted>', 'gi'))) AS normalized_query,
    lower(CASE WHEN source_query = '' THEN source_url ELSE regexp_replace(source_url, '\?.*$', '') || '?' ||
      regexp_replace(source_query, '((token|key|secret|password|passwd|signature|auth|session)[^=&]*=)[^&]*', '\1<redacted>', 'gi') END) AS normalized_url
  FROM source
), candidates AS (
  SELECT *,
    CASE
      WHEN regexp_matches(normalized_path, '/geoserver/(wms|wfs|ows|web)') THEN 'GeoServer'
      WHEN regexp_matches(normalized_path, '/app/rest/|/login\.html$|teamcity') THEN 'JetBrains TeamCity'
      WHEN regexp_matches(normalized_path, '/jnlpjars/jenkins-cli\.jar|/cli/?$|/jenkins/') THEN 'Jenkins'
      WHEN regexp_matches(normalized_path, '/users/password|/api/v4/|/gitlab/') THEN 'GitLab'
      WHEN regexp_matches(normalized_path, '/public/plugins/') THEN 'Grafana'
      WHEN regexp_matches(normalized_path, '/wp-content/plugins/wp-automatic/') THEN 'WordPress Automatic'
      WHEN regexp_matches(normalized_path, '/wp-content/plugins/gutenberg/') THEN 'Gutenberg'
      WHEN regexp_matches(normalized_path, '/wp-includes/|/wp-login\.php') THEN 'WordPress'
      WHEN regexp_matches(normalized_path, '/php-cgi/|/cgi-bin/php(?:\.exe)?') THEN 'PHP'
      WHEN regexp_matches(normalized_path, 'spring-cloud-config|/configserver/|/actuator/env') THEN 'Spring Cloud Config'
      WHEN regexp_matches(normalized_path, '/actuator/') THEN 'Spring Framework'
      WHEN regexp_matches(normalized_path, '/webtools/|/partymgr/|/ofbiz/') THEN 'Apache OFBiz'
      WHEN regexp_matches(normalized_path, '/clients/mycrl|checkpoint|/mobileaccess/') THEN 'Check Point Quantum Gateway'
      WHEN regexp_matches(normalized_path, '/mics/|mobileiron/sentry|/sentry/admin') THEN 'Ivanti Sentry'
      WHEN regexp_matches(normalized_path, '/roundcube/|/webmail/.*roundcube|/roundcubemail/') THEN 'Roundcube Webmail'
      WHEN regexp_matches(normalized_path, '/cgi-sys/|/cpsess[0-9]+/|/webcall/') THEN 'cPanel'
      WHEN regexp_matches(normalized_path, '/thinclient/|/aht/|athenticate\.asp') THEN 'WS_FTP Server'
      WHEN regexp_matches(normalized_path, '/catalog-portal/|/saas/auth/') THEN 'VMware Workspace ONE Access'
      WHEN regexp_matches(normalized_path, '/struts/|upload\.action$|struts.*\.action$') THEN 'Apache Struts'
      WHEN regexp_matches(normalized_path, '/graphs/[^/]+/(gremlin|schema|vertices|edges)|/gremlin') THEN 'Apache HugeGraph'
      WHEN regexp_matches(normalized_path, 'insertclient\.php') THEN 'Aegon Life'
      WHEN regexp_matches(normalized_path, 'log4j-core[^/]*\.jar') THEN 'Apache Log4j'
      WHEN regexp_matches(normalized_path, '/rest/(all/)?v1/|/static/version[0-9]+/') THEN 'Adobe Commerce'
      WHEN regexp_matches(normalized_path, '/api/index\.php/v1/|/administrator/index\.php') THEN 'Joomla'
      WHEN regexp_matches(normalized_path, '/_utils/|/_all_dbs') THEN 'Apache CouchDB'
      WHEN regexp_matches(normalized_path, 'sharefile|storagezones') THEN 'Citrix ShareFile'
      WHEN regexp_matches(normalized_path, '/setupwizard\.aspx|screenconnect|/host#access') THEN 'ConnectWise ScreenConnect'
      WHEN regexp_matches(normalized_path, '/\+cscoe\+/|/\+cscot\+/') THEN 'Cisco ASA/FTD'
      WHEN regexp_matches(normalized_path, '/_layouts/15/') THEN 'Microsoft SharePoint'
      WHEN regexp_matches(normalized_path, '(/api/)?jolokia|:8161/admin') THEN 'Jolokia/ActiveMQ'
      WHEN regexp_matches(normalized_path, '/global-protect/') THEN 'PAN-OS'
      WHEN regexp_matches(normalized_path, '/mgmt/(tm|shared)/') THEN 'F5 BIG-IP'
      WHEN regexp_matches(normalized_path, 'setupadministrator|/template/custom/') THEN 'Atlassian Confluence'
      WHEN regexp_matches(normalized_path, '/manager/(html|text)|/host-manager/') THEN 'Apache Tomcat'
      WHEN regexp_matches(normalized_path, '/(jmx-console|web-console)/|/invoker/') THEN 'JBoss'
      WHEN regexp_matches(normalized_path, '(^|/)(script|scripttext)$|/computer/[^/]+/script') THEN 'Jenkins'
      WHEN regexp_matches(normalized_path, '/console/|/wls-wsat/|/_async/') THEN 'Oracle WebLogic'
      WHEN regexp_matches(normalized_path, '/solr/') THEN 'Apache Solr'
      WHEN regexp_matches(normalized_path, 'eval-stdin\.php$') THEN 'PHPUnit'
      WHEN regexp_matches(normalized_path, '/_ignition/') THEN 'Laravel Ignition'
      WHEN regexp_matches(normalized_path, '/(autodiscover|ews|ecp)/') THEN 'Microsoft Exchange'
      WHEN regexp_matches(normalized_path, 'vropspluginui') THEN 'VMware vCenter'
      WHEN regexp_matches(normalized_path, '/remote/fgt_lang|/sslvpn') THEN 'Fortinet FortiOS'
      WHEN regexp_matches(normalized_path, '/cacti/') THEN 'Cacti'
      WHEN regexp_matches(normalized_path, '/cfide/') THEN 'Adobe ColdFusion'
      WHEN regexp_matches(normalized_path, '/service/soap') THEN 'Zimbra Collaboration'
      WHEN regexp_matches(normalized_path, '/goanywhere/') THEN 'GoAnywhere MFT'
      WHEN regexp_matches(normalized_path, 'moveitisapi|/machine\.aspx') THEN 'MOVEit Transfer'
      WHEN regexp_matches(normalized_path, '/webinterface/') THEN 'CrushFTP'
      WHEN regexp_matches(normalized_path, '/mifs/|/rs/api/v2/') THEN 'Ivanti EPMM'
      WHEN regexp_matches(normalized_path, '/api/v1/(totp|cav|configuration)') THEN 'Ivanti Connect Secure'
      WHEN regexp_matches(normalized_path, '/oauth/idp/|/logon/logonpoint/') THEN 'Citrix NetScaler Gateway'
      WHEN regexp_matches(normalized_path, '/vpn/index\.html') THEN 'Citrix NetScaler Gateway'
      WHEN regexp_matches(normalized_path, '/setup/setup-[^/]*\.jsp$') THEN 'Openfire'
      WHEN regexp_matches(normalized_path, '/minio/') THEN 'MinIO'
      WHEN regexp_matches(normalized_path, '/nacos/') THEN 'Nacos'
      WHEN regexp_matches(normalized_path, '/apisix/') THEN 'Apache APISIX'
      WHEN regexp_matches(normalized_path, '/druid/') THEN 'Apache Druid'
      WHEN regexp_matches(normalized_path, '/sdk/weblanguage') THEN 'Hikvision IP Camera'
      WHEN regexp_matches(normalized_path, '/api/v1/validate/code|/langflow') THEN 'Langflow'
      WHEN regexp_matches(normalized_path, '/nifi') THEN 'Apache NiFi'
      WHEN regexp_matches(normalized_path, '/airflow|/api/v1/dags') THEN 'Apache Airflow'
      WHEN regexp_matches(normalized_path, '/grafana') THEN 'Grafana'
      WHEN regexp_matches(normalized_path, '/kibana') THEN 'Kibana'
      WHEN regexp_matches(normalized_path, '/wd/hub') THEN 'Selenium Grid'
      WHEN regexp_matches(normalized_path, '/terminals/') THEN 'Jupyter'
      WHEN regexp_matches(normalized_path, '/_cat/|/_cluster/|/_nodes/') THEN 'Elasticsearch'
      WHEN regexp_matches(normalized_path, '/v[12]/keys') THEN 'etcd'
      WHEN regexp_matches(normalized_path, 'jquery') THEN 'jQuery'
      WHEN regexp_matches(normalized_path, 'pdf(\.min)?\.js') THEN 'PDF.js'
      WHEN regexp_matches(normalized_path, 'angular') THEN 'AngularJS'
      WHEN regexp_matches(normalized_path, 'lodash') THEN 'Lodash'
      WHEN regexp_matches(normalized_path, 'bootstrap') THEN 'Bootstrap'
      WHEN regexp_matches(normalized_path, 'purify') THEN 'DOMPurify'
      WHEN regexp_matches(normalized_path, 'ckeditor') THEN 'CKEditor'
      WHEN regexp_matches(normalized_path, 'tinymce') THEN 'TinyMCE'
      WHEN regexp_matches(normalized_path, 'underscore(?:\.min)?\.js') THEN 'Underscore.js'
      WHEN regexp_matches(normalized_path, 'axios(?:\.min)?\.js') THEN 'Axios'
      WHEN regexp_matches(normalized_path, '(?:node-)?semver(?:\.min)?\.js') THEN 'Semver'
      WHEN regexp_matches(normalized_path, '(^|/)ini(?:\.min)?\.js') THEN 'ini'
      WHEN regexp_matches(normalized_path, '(^|/)\.env([./]|$)') THEN 'Sensitive file'
      WHEN regexp_matches(normalized_path, '/\.git/') THEN 'Git metadata'
      WHEN regexp_matches(normalized_path, '(wp-config|settings\.php|id_rsa|id_ed25519|credentials|\.(sql|dump|sqlite3?|tfstate|tfvars|bak|map)(\.|$))') THEN 'Sensitive file'
      ELSE 'Generic security endpoint'
    END AS product_hint,
    CASE
      WHEN regexp_matches(normalized_path, '(^|/)\.env([./]|$)|/\.git/|wp-config|settings\.php|id_rsa|id_ed25519|credentials|\.(sql|dump|sqlite3?|tfstate|tfvars|bak)(\.|$)') THEN 'SECRET_FILE_PATH_OBSERVED'
      WHEN regexp_matches(normalized_path, '(jquery|pdf(\.min)?\.js|angular|lodash|bootstrap|purify|ckeditor|tinymce|underscore|axios|semver|ini(?:\.min)?\.js)') THEN 'CLIENT_COMPONENT_PATH_OBSERVED'
      WHEN regexp_matches(normalized_path, '(swagger|openapi|graphql|graphiql|actuator|server-status|phpinfo|elmah|trace\.axd)') THEN 'EXPOSURE_ENDPOINT_OBSERVED'
      ELSE 'PRODUCT_ENDPOINT_OBSERVED'
    END AS observed_signal,
    CASE
      WHEN regexp_matches(normalized_path, '/geoserver/(wms|wfs|ows)|eval-stdin\.php$|/_ignition/execute-solution|/minio/bootstrap/v1/verify|/api/v1/validate/code') THEN 0.75
      WHEN regexp_matches(normalized_path, '/(app/rest|global-protect|mgmt/tm|service/soap|druid|apisix|nacos|jolokia)/') THEN 0.60
      ELSE 0.35
    END AS endpoint_confidence,
    CASE
      WHEN regexp_matches(normalized_path, 'geoserver') THEN 'geoserver,cve-2024-36401'
      WHEN regexp_matches(normalized_path, 'jolokia') THEN 'activemq,jolokia'
      WHEN regexp_matches(normalized_path, 'global-protect') THEN 'panos,cve-2024-3400'
      WHEN regexp_matches(normalized_path, 'jenkins|jnlpjars') THEN 'jenkins,cve-2024-23897'
      WHEN regexp_matches(normalized_path, 'grafana') THEN 'grafana,cve-2021-43798'
      WHEN regexp_matches(normalized_path, 'wp-automatic') THEN 'wordpress-plugin,wp-automatic'
      WHEN regexp_matches(normalized_path, 'jquery') THEN 'jquery,client-component'
      WHEN regexp_matches(normalized_path, '(^|/)\.env') THEN 'exposure,secrets'
      ELSE 'fingerprint,passive-validation'
    END AS suggested_validation_tags
  FROM normalized
  WHERE regexp_matches(normalized_path,
    '(\.env|/\.git/|\.map$|\.(sql|dump|sqlite|bak|tfstate|tfvars)|wp-config|settings\.php|id_rsa|id_ed25519|credentials|actuator|app/rest|login\.html$|teamcity|jnlpjars/jenkins-cli|/cli/?$|/jenkins/|users/password|/gitlab/|public/plugins|wp-content/plugins/(wp-automatic|gutenberg)|wp-includes|wp-login\.php|php-cgi|cgi-bin/php|spring-cloud-config|configserver|/webtools/|/partymgr/|/ofbiz/|clients/mycrl|checkpoint|mobileaccess|/mics/|mobileiron/sentry|sentry/admin|roundcube|cgi-sys|cpsess|/webcall/|thinclient|/aht/|athenticate\.asp|catalog-portal|/saas/auth/|/struts/|upload\.action|/graphs/[^/]+/(gremlin|schema|vertices|edges)|/gremlin|insertclient\.php|log4j-core[^/]*\.jar|/rest/(all/)?v1/|static/version[0-9]+|api/index\.php/v1|administrator/index\.php|/_utils/|sharefile|storagezones|setupwizard\.aspx|screenconnect|/\+cscoe\+/|/\+cscot\+/|/_layouts/15/|geoserver|jolokia|global-protect|mgmt/tm|setupadministrator|setup/setup-|oauth/idp|logon/logonpoint|vpn/index\.html|manager/(html|text)|jmx-console|web-console|invoker|wls-wsat|_ignition|eval-stdin|autodiscover|/ews/|/ecp/|vropspluginui|remote/fgt_lang|sslvpn|/cacti/|/cfide/|service/soap|goanywhere|moveitisapi|webinterface|/mifs/|/minio/|/nacos/|/apisix/|/druid/|sdk/weblanguage|validate/code|langflow|nifi|airflow|grafana|kibana|swagger|openapi|graphql|graphiql|phpinfo|server-status|api/v4|wd/hub|terminals|_cat|/_cluster/|/_nodes/|_all_dbs|v[12]/keys|jquery|pdf(\.min)?\.js|angular|lodash|bootstrap|purify|ckeditor|tinymce|underscore(\.min)?\.js|axios(\.min)?\.js|(node-)?semver(\.min)?\.js|(^|/)ini(\.min)?\.js)')
    OR regexp_matches(lower(url), 'https?://(cdn\.polyfill\.io|polyfill\.io|bootcdn\.net|bootcss\.com)/')
)
SELECT * FROM candidates
) TO '__OUTPUT__' (FORMAT PARQUET, COMPRESSION ZSTD);
