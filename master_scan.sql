INSTALL httpfs;
LOAD httpfs;

-- Ressourcen- und Verbindungskonfiguration
SET preserve_insertion_order = false;

COPY (
    WITH prefiltered_assets AS (
        SELECT
            url_host_registered_domain,
            url_host_name,
            url,
            fetch_status,
            -- Native Spalte url_path => kein Query-String, kein Hostname im Match.
            -- FP-Fix: frueher matchte '%.git%' auch Hosts wie github.io
            lower(url_path) AS path,
            lower(url_host_name) AS host
        FROM read_parquet([__PARQUET_PATHS__])
        WHERE subset = 'warc'
          -- 404 wird fuer Subdomain-Takeover-Kandidaten (unclaimed Services) benoetigt
          AND fetch_status IN (200, 301, 302, 401, 403, 404)
          AND (
              -- === A) Pfad-basierter Prefilter (case-insensitiv, breit fuer Recall) ===
              -- 1. Sensitive Files & Backups
              url_path ILIKE '%.env%' OR url_path ILIKE '%/.git/%' OR url_path ILIKE '%.map%'
              OR url_path ILIKE '%.sql%' OR url_path ILIKE '%.dump%' OR url_path ILIKE '%.sqlite%'
              OR url_path ILIKE '%.bak%' OR url_path ILIKE '%.zip%' OR url_path ILIKE '%.tar.gz%'
              OR url_path ILIKE '%.tfstate%' OR url_path ILIKE '%.tfvars%' OR url_path ILIKE '%.postman%'
              OR url_path ILIKE '%id_rsa%' OR url_path ILIKE '%id_ed25519%' OR url_path ILIKE '%credentials%'
              OR url_path ILIKE '%settings.php%' OR url_path ILIKE '%wp-config%'
              -- 2. Enterprise RCEs, Gateways, Admin-Panels & Actuators
              OR url_path ILIKE '%/actuator/%' OR url_path ILIKE '%/app/rest/%' OR url_path ILIKE '%/geoserver/%'
              OR url_path ILIKE '%/jolokia%' OR url_path ILIKE '%/api/v1/totp%'
              OR url_path ILIKE '%/oauth/idp/%' OR url_path ILIKE '%setupadministrator%' OR url_path ILIKE '%/nifi%'
              OR url_path ILIKE '%/airflow%' OR url_path ILIKE '%/mgmt/tm/%' OR url_path ILIKE '%phpinfo%'
              OR url_path ILIKE '%swagger%' OR url_path ILIKE '%openapi%' OR url_path ILIKE '%graphql%' OR url_path ILIKE '%graphiql%'
              OR url_path ILIKE '%/manager/html%' OR url_path ILIKE '%/manager/text%' OR url_path ILIKE '%/host-manager%'
              OR url_path ILIKE '%/jmx-console%' OR url_path ILIKE '%/web-console%' OR url_path ILIKE '%/invoker/%'
              OR url_path ILIKE '%/console/%' OR url_path ILIKE '%/wls-wsat%' OR url_path ILIKE '%/script%'
              OR url_path ILIKE '%/solr/%' OR url_path ILIKE '%eval-stdin.php%' OR url_path ILIKE '%_ignition%'
              OR url_path ILIKE '%autodiscover%' OR url_path ILIKE '%/ews/%' OR url_path ILIKE '%/ecp/%'
              OR url_path ILIKE '%vropspluginui%' OR url_path ILIKE '%/remote/fgt_lang%' OR url_path ILIKE '%global-protect%'
              OR url_path ILIKE '%/cacti/%' OR url_path ILIKE '%/cfide/%' OR url_path ILIKE '%/service/soap%'
              OR url_path ILIKE '%/goanywhere/%' OR url_path ILIKE '%moveitisapi%' OR url_path ILIKE '%/webinterface/%'
              OR url_path ILIKE '%/mifs/%' OR url_path ILIKE '%/kibana%' OR url_path ILIKE '%/grafana%'
              OR url_path ILIKE '%/minio/%' OR url_path ILIKE '%/nacos/%' OR url_path ILIKE '%/apisix/%'
              OR url_path ILIKE '%/phpmyadmin%' OR url_path ILIKE '%/_cat/%' OR url_path ILIKE '%_all_dbs%'
              OR url_path ILIKE '%/v1/keys%' OR url_path ILIKE '%/v2/keys%' OR url_path ILIKE '%/terminals/%'
              OR url_path ILIKE '%/wd/hub%' OR url_path ILIKE '%/druid/%' OR url_path ILIKE '%/sdk/weblanguage%'
              OR url_path ILIKE '%/api/v4/%' OR url_path ILIKE '%/jenkins%' OR url_path ILIKE '%/teamcity%'
              OR url_path ILIKE '%/bamboo/%' OR url_path ILIKE '%/portainer%' OR url_path ILIKE '%/rancher%'
              OR url_path ILIKE '%/harbor%' OR url_path ILIKE '%/artifactory%' OR url_path ILIKE '%/zabbix/%'
              OR url_path ILIKE '%/nagios%' OR url_path ILIKE '%/centreon%' OR url_path ILIKE '%/prometheus%'
              OR url_path ILIKE '%elmah%' OR url_path ILIKE '%trace.axd%' OR url_path ILIKE '%server-status%'
              OR url_path ILIKE '%server-info%' OR url_path ILIKE '%.ds_store%'
              -- 3. AI / LLM Infrastruktur
              OR url_path ILIKE '%/api/jobs/%' OR url_path ILIKE '%/api/generate%' OR url_path ILIKE '%/api/tags%'
              OR url_path ILIKE '%/ajax-api/2.0/mlflow%' OR url_path ILIKE '%/api/v1/validate/code%'
              OR url_path ILIKE '%/langflow%' OR url_path ILIKE '%/flowise%' OR url_path ILIKE '%/anything-llm%'
              OR url_path ILIKE '%/comfyui%' OR url_path ILIKE '%/v1/models%'
              -- 4. Client-Side Libraries & CDNs
              OR url_path ILIKE '%pdf.js%' OR url_path ILIKE '%pdf.min.js%' OR url_path ILIKE '%polyfill%'
              OR url_path ILIKE '%bootcdn%' OR url_path ILIKE '%angular%' OR url_path ILIKE '%jquery%'
              OR url_path ILIKE '%lodash%' OR url_path ILIKE '%bootstrap%' OR url_path ILIKE '%purify%'
              OR url_path ILIKE '%ckeditor%' OR url_path ILIKE '%tinymce%' OR url_path ILIKE '%/ajax/libs/%'
              OR url_path ILIKE '%/npm/%'
              -- === B) Host-Prefilter: Subdomain-Takeover-Kandidaten (404 auf takeover-anfaelligen Services) ===
              OR (
                  fetch_status = 404
                  AND regexp_matches(lower(url_host_name),
                      '(s3[.-].*amazonaws\.com|github\.io|gitlab\.io|bitbucket\.io|herokuapp\.com|azurewebsites\.net|cloudapp\.net|trafficmanager\.net|azurefd\.net|blob\.core\.windows\.net|web\.core\.windows\.net|cloudfront\.net|netlify\.app|vercel\.app|surge\.sh|onrender\.com|fly\.dev|railway\.app|pythonanywhere\.com|wpengine\.com|pantheonsite\.io|wordpress\.com|myshopify\.com|tumblr\.com|ghost\.io|webflow\.io|readthedocs\.io|pages\.dev|workers\.dev|web\.app|firebaseapp\.com|strikingly\.com|tilda\.ws|zendesk\.com|freshdesk\.com|helpjuice\.com|unbouncepages\.com|cargo\.site|squarespace\.com|wixsite\.com)$')
              )
          )
    ),
    classified AS (
        SELECT
            url_host_registered_domain,
            url_host_name,
            url,
            fetch_status,
            path,
            host,
            -- =================================================================
            -- 1. Schwachstellen- & Exploit-Klassifizierung
            -- =================================================================
            CASE
                -- --- SUBDOMAIN TAKEOVER KANDIDATEN (404 = unclaimed Service) ---
                WHEN fetch_status = 404 AND regexp_matches(host, 's3[.-].*amazonaws\.com$')
                    THEN 'TAKEOVER_CANDIDATE_S3_UNCLAIMED_BUCKET'
                WHEN fetch_status = 404 AND regexp_matches(host, '(github|gitlab|bitbucket)\.io$')
                    THEN 'TAKEOVER_CANDIDATE_PAGES_UNCLAIMED'
                WHEN fetch_status = 404 AND regexp_matches(host, 'herokuapp\.com$')
                    THEN 'TAKEOVER_CANDIDATE_HEROKU_UNCLAIMED_APP'
                WHEN fetch_status = 404 AND regexp_matches(host, '(azurewebsites\.net|cloudapp\.net|trafficmanager\.net|azurefd\.net|blob\.core\.windows\.net|web\.core\.windows\.net)$')
                    THEN 'TAKEOVER_CANDIDATE_AZURE_UNCLAIMED'
                WHEN fetch_status = 404 AND regexp_matches(host, 'cloudfront\.net$')
                    THEN 'TAKEOVER_CANDIDATE_CLOUDFRONT_DANGLING'
                WHEN fetch_status = 404 AND regexp_matches(host, '(netlify\.app|vercel\.app|surge\.sh|onrender\.com|fly\.dev|railway\.app|pythonanywhere\.com)$')
                    THEN 'TAKEOVER_CANDIDATE_DEPLOY_PLATFORM'
                WHEN fetch_status = 404 AND regexp_matches(host, '(wpengine\.com|pantheonsite\.io|wordpress\.com|myshopify\.com|tumblr\.com|ghost\.io|webflow\.io|readthedocs\.io|pages\.dev|workers\.dev|web\.app|firebaseapp\.com|strikingly\.com|tilda\.ws|zendesk\.com|freshdesk\.com|helpjuice\.com|unbouncepages\.com|cargo\.site|squarespace\.com|wixsite\.com)$')
                    THEN 'TAKEOVER_CANDIDATE_CMS_SAAS'

                -- --- CRITICAL ENTERPRISE RCEs & AUTH BYPASSES (CVSS 9.0 - 10.0) ---
                WHEN regexp_matches(path, '/app/rest/(users/id:1/tokens|server|version)')
                    THEN 'RCE_TEAMCITY_AUTH_BYPASS_CVE-2024-27198'
                WHEN regexp_matches(path, '/geoserver/(wms|wfs|ows)')
                    THEN 'RCE_GEOSERVER_CVE-2024-36401'
                WHEN regexp_matches(path, '(/api/jolokia/exec/|/jolokia/list|:8161/admin/)')
                    THEN 'RCE_ACTIVEMQ_JOLOKIA_CVE-2023-46604'
                WHEN regexp_matches(path, '/api/v1/(totp/user-backup-code|cav/client/status|configuration/users)')
                    THEN 'RCE_IVANTI_CONNECT_SECURE'
                WHEN regexp_matches(path, '(/setup/setupadministrator\.action|/setup/finishsetup\.action|/template/custom/)')
                    THEN 'RCE_CONFLUENCE_AUTH_BYPASS_CVE-2023-22527'
                WHEN regexp_matches(path, '/mgmt/tm/util/bash|/mgmt/shared/authn/login')
                    THEN 'RCE_F5_BIGIP_ICONTROL_CVE-2022-1388'
                -- NEU: zusaetzliche RCE-Angriffsflaechen
                WHEN regexp_matches(path, '/manager/(html|text)|/host-manager/html')
                    THEN 'RCE_TOMCAT_MANAGER_WAR_UPLOAD'
                WHEN regexp_matches(path, '/(jmx-console|web-console)/|/invoker/(JMXInvokerServlet|EJBInvokerServlet)')
                    THEN 'RCE_JBOSS_CONSOLE_UNAUTH'
                WHEN regexp_matches(path, '^/(script|scripttext)$|/computer/[^/]+/script')
                    THEN 'RCE_JENKINS_SCRIPT_CONSOLE'
                WHEN regexp_matches(path, '/console/(login|jndi)|/wls-wsat/|/_async/')
                    THEN 'RCE_WEBLOGIC_CVE-2020-14882'
                WHEN regexp_matches(path, '/solr/(admin|#/)|/solr/[^/]+/(config|schema)')
                    THEN 'RCE_SOLR_UNAUTH_CVE-2019-17558'
                WHEN regexp_matches(path, 'eval-stdin\.php$')
                    THEN 'RCE_PHPUNIT_CVE-2017-9841'
                WHEN regexp_matches(path, '/_ignition/(execute-solution|health-check)')
                    THEN 'RCE_LARAVEL_IGNITION_CVE-2021-3129'
                WHEN regexp_matches(path, '/autodiscover/autodiscover\.json|/ews/exchange\.asmx|/ecp/')
                    THEN 'RCE_EXCHANGE_PROXYLOGON_PROXYSHELL'
                WHEN regexp_matches(path, '/ui/vropspluginui/rest/services/uploadova')
                    THEN 'RCE_VMWARE_VCENTER_CVE-2021-21972'
                WHEN regexp_matches(path, '/remote/fgt_lang|/sslvpn')
                    THEN 'RCE_FORTINET_SSLVPN_CVE-2024-21762'
                WHEN regexp_matches(path, '/global-protect/(login|portal)')
                    THEN 'RCE_PANOS_CVE-2024-3400'
                WHEN regexp_matches(path, '/cacti/(index\.php|remote_agent\.php)')
                    THEN 'RCE_CACTI_CVE-2022-46169'
                WHEN regexp_matches(path, '/cfide/(administrator|adminapi|componentutils)')
                    THEN 'RCE_COLDFUSION_CVE-2023-26360'
                WHEN regexp_matches(path, '/service/soap')
                    THEN 'RCE_ZIMBRA_CVE-2024-45519'
                WHEN regexp_matches(path, '/goanywhere/(admin|api)')
                    THEN 'RCE_GOANYWHERE_CVE-2023-0669'
                WHEN regexp_matches(path, '/moveitisapi/|/machine\.aspx')
                    THEN 'RCE_MOVEIT_CVE-2023-34362'
                WHEN regexp_matches(path, '/webinterface/(login|function)')
                    THEN 'RCE_CRUSHFTP_CVE-2025-31161'
                WHEN regexp_matches(path, '/mifs/|/rs/api/v2/')
                    THEN 'RCE_IVANTI_EPMM_CVE-2023-35082'
                WHEN regexp_matches(path, '/minio/bootstrap/v1/verify')
                    THEN 'LEAK_MINIO_CREDS_CVE-2023-28432'
                WHEN regexp_matches(path, '/nacos/v1/(auth|cs|ns)/')
                    THEN 'RCE_NACOS_UNAUTH'
                WHEN regexp_matches(path, '/apisix/(admin|routes)')
                    THEN 'RCE_APISIX_CVE-2022-24112'
                WHEN regexp_matches(path, '/_cat/(indices|nodes)|_all_dbs$')
                    THEN 'EXPOSURE_ELASTICSEARCH_COUCHDB_UNAUTH'
                WHEN regexp_matches(path, '/v[12]/keys/')
                    THEN 'EXPOSURE_ETCD_UNAUTH'
                WHEN regexp_matches(path, '/terminals/[0-9a-z]+|/api/terminals')
                    THEN 'RCE_JUPYTER_UNAUTH_TERMINAL'
                WHEN regexp_matches(path, '/wd/hub/(session|status)|/selenium/')
                    THEN 'RCE_SELENIUM_GRID_UNAUTH'
                WHEN regexp_matches(path, '/druid/(indexer/v1/task|coordinator|overlord)')
                    THEN 'RCE_DRUID_CVE-2021-25646'
                WHEN regexp_matches(path, '/sdk/weblanguage')
                    THEN 'RCE_HIKVISION_CVE-2021-36260'
                WHEN regexp_matches(path, '/api/v1/validate/code')
                    THEN 'RCE_LANGFLOW_CVE-2025-3248'
                WHEN regexp_matches(path, '/phpmyadmin/(setup|index\.php)|/pma/')
                    THEN 'EXPOSURE_PHPMYADMIN'
                WHEN regexp_matches(path, '/setup/setup-[^/]*\.jsp$')
                    THEN 'RCE_OPENFIRE_CVE-2023-32315'

                -- --- AI / ML & CLUSTER INFRASTRUCTURE EXPOSURE ---
                WHEN regexp_matches(path, '(/api/jobs/|/api/generate|/api/tags|/ajax-api/2\.0/mlflow/models|/langflow|/flowise|/anything-llm|/comfyui|/v1/models$)')
                    THEN 'EXPOSURE_AI_CLUSTER_UNAUTH_RCE (Ray/Ollama/MLflow/Langflow/Flowise/ComfyUI)'

                -- --- DEVOPS, PIPELINES & ACTUATORS ---
                WHEN regexp_matches(path, '/actuator/(env|heapdump|gateway|beans|loggers|httptrace|mappings)')
                    THEN 'EXPOSURE_SPRING_BOOT_ACTUATOR'
                WHEN regexp_matches(path, '(/nifi-api/controller/process-groups|/airflow/home|/api/v1/dags)')
                    THEN 'EXPOSURE_DATA_PIPELINE_UNAUTH (NiFi/Airflow)'
                WHEN regexp_matches(path, '/oauth/idp/\.well-known/openid-configuration|/logon/LogonPoint/index\.html')
                    THEN 'EXPOSURE_CITRIX_NETSCALER_GATEWAY'
                WHEN regexp_matches(path, '/api/v4/(projects|users|groups)')
                    THEN 'EXPOSURE_GITLAB_API'
                WHEN regexp_matches(path, '/(jenkins|teamcity|bamboo)/(manage|script|configure|admin)')
                    THEN 'EXPOSURE_CI_CD_ADMIN'
                WHEN regexp_matches(path, '/(portainer|harbor)/api/|/rancher/v3')
                    THEN 'EXPOSURE_CONTAINER_ORCHESTRATION'
                WHEN regexp_matches(path, '/(zabbix|nagios|centreon|prometheus|grafana)/(api|index\.php|setup)?')
                    THEN 'EXPOSURE_MONITORING_STACK'
                WHEN regexp_matches(path, '/kibana/(api|app)')
                    THEN 'EXPOSURE_KIBANA'
                WHEN regexp_matches(path, '/(artifactory|nexus)/(api|service)')
                    THEN 'EXPOSURE_ARTIFACT_REGISTRY'

                -- --- CREDENTIALS, SECRETS & SOURCE CODE LEAKS (am Pfadende verankert) ---
                WHEN regexp_matches(path, '(^|/)\.env(\.[a-z0-9_-]+)?$')
                    THEN 'LEAK_ENV_SECRETS'
                WHEN regexp_matches(path, '/\.git/(config|head|index|packed-refs|refs/.+)$')
                    THEN 'LEAK_GIT_REPO'
                WHEN regexp_matches(path, '(^|/)(id_rsa|id_ed25519)$|(^|/)\.aws/credentials$|(^|/)credentials\.(json|xml|ya?ml|ini|txt|php|enc)$')
                    THEN 'LEAK_SSH_OR_CLOUD_KEYS'
                WHEN regexp_matches(path, '\.(tfstate|tfvars)$|postman_(collection|environment)\.json$')
                    THEN 'LEAK_TERRAFORM_OR_POSTMAN_KEYS'
                WHEN regexp_matches(path, '(^|/)(settings\.php|wp-config\.php|configuration\.php|config\.inc\.php)(\.(bak|old|save|swp|txt))?$')
                    THEN 'LEAK_CMS_CONFIG'
                WHEN regexp_matches(path, '\.(sql|dump|sqlite|sqlite3|db|mdb)(\.gz|\.bz2|\.zip)?$')
                     OR regexp_matches(path, '(backup|site|www|database|dump|db)[-._0-9a-z]*\.(zip|tar\.gz|tar\.bz2|7z|rar)$')
                    THEN 'LEAK_DATABASE_OR_FULL_BACKUP'
                WHEN regexp_matches(path, '\.(js|css)\.map$')
                    THEN 'EXPOSURE_SOURCE_MAP_WHITEBOX'
                WHEN regexp_matches(path, '(phpinfo\.php|elmah\.axd|trace\.axd|server-status$|server-info$|\.ds_store$|web\.config\.bak$)')
                    THEN 'EXPOSURE_DEBUG_INFO_DISCLOSURE'
                WHEN regexp_matches(path, '/(swagger|openapi)\.(json|yaml|yml)$|/v[23]/api-docs$|/(graphiql|graphql)$')
                    THEN 'EXPOSURE_API_SCHEMA_GRAPHQL'

                -- --- SUPPLY CHAIN & CLIENT-SIDE CVEs ---
                WHEN regexp_matches(url, '(?i)https?://(cdn\.polyfill\.io|polyfill\.io|bootcdn\.net|bootcss\.com)/')
                    THEN 'SUPPLY_CHAIN_MALICIOUS_CDN'
                WHEN regexp_matches(path, 'pdf(\.min)?\.js(\?ver=|@)?([0-3]\.[0-9]+|4\.[0-1](\.[0-9]+)?)')
                    THEN 'CLIENT_PDFJS_ARBITRARY_JS_CVE-2024-4367'
                WHEN regexp_matches(path, '(angular|angularjs)[@/\-_](1\.[0-8](\.[0-9]+)?(\.min)?\.js)')
                    THEN 'CLIENT_ANGULAR_1X_CSTI'
                WHEN regexp_matches(path, 'jquery[@/\-_]((1|2)\.[0-9]+(\.[0-9]+)?|3\.[0-4](\.[0-9]+)?)(\.slim)?(\.min)?\.js')
                    THEN 'CLIENT_JQUERY_XSS_CVE-2020-11022'
                WHEN regexp_matches(path, 'jquery[\-_]ui[@/\-_](1\.(1[0-2]|[0-9])(\.[0-9]+)?)(\.min)?\.js')
                    THEN 'CLIENT_JQUERY_UI_XSS_CVE-2021-41182'
                WHEN regexp_matches(path, 'lodash[@/\-_]([0-3]\.[0-9]+|4\.(0|[1-9]|1[0-6])(\.[0-9]+)?)(\.min)?\.js')
                    THEN 'CLIENT_LODASH_PROTO_POLLUTION'
                WHEN regexp_matches(path, 'bootstrap[@/\-_]([2-3]\.[0-9]+|4\.[0-2](\.[0-9]+)?)(\.min)?\.js')
                    THEN 'CLIENT_BOOTSTRAP_XSS'
                WHEN regexp_matches(path, 'purify[@/\-_]([0-1]\.[0-9]+|2\.[0-3](\.[0-9]+)?)(\.min)?\.js')
                    THEN 'CLIENT_DOMPURIFY_BYPASS'
                WHEN regexp_matches(path, '(ckeditor|tinymce)[@/\-_]([1-4]\.[0-9]+(\.[0-9]+)?)(\.min)?\.js')
                    THEN 'CLIENT_EDITOR_STORED_XSS'
                ELSE 'OTHER_TARGET_ENDPOINT'
            END AS vulnerability_class,

            -- =================================================================
            -- 2. Confidence-Level (Nachfilter: HIGH zuerst pruefen)
            -- =================================================================
            CASE
                -- HIGH: spezifische Exploit-Pfade / eindeutige Secret-Dateien
                WHEN regexp_matches(path, '(eval-stdin\.php$|/_ignition/execute-solution|vropspluginui|/mgmt/tm/util/bash|/api/jolokia/exec/|setupadministrator|/remote/fgt_lang|/global-protect/login|/cfide/|/service/soap|moveitisapi|/mifs/|/api/v1/totp|/app/rest/(users/id:1/tokens|server|version)|/geoserver/(wms|wfs|ows)|/actuator/(heapdump|env|gateway)|/api/v1/validate/code|/minio/bootstrap/v1/verify|/druid/indexer/v1/task|/terminals/|/wd/hub/|/manager/(html|text)|/jmx-console/|/invoker/|/console/(login|jndi)|/wls-wsat/|/solr/(admin|#/)|autodiscover\.json|/ews/exchange\.asmx|/nacos/v1/|/apisix/admin|/sdk/weblanguage|/nifi-api/|/oauth/idp/)')
                    THEN 'HIGH'
                WHEN regexp_matches(path, '(^|/)\.env(\.[a-z0-9_-]+)?$|/\.git/(config|head|packed-refs)$|(id_rsa|id_ed25519)$|\.tfstate$|postman_(collection|environment)\.json$|(^|/)(settings\.php|wp-config\.php|configuration\.php)(\.(bak|old|save))?$|\.(sql|dump|sqlite3?|mdb)(\.gz|\.bz2|\.zip)?$')
                    THEN 'HIGH'
                -- MEDIUM: Takeover-Kandidaten (DNS-Verifikation noetig) + Admin-Panels/Exposures
                WHEN fetch_status = 404 AND regexp_matches(host, '(amazonaws\.com|github\.io|gitlab\.io|bitbucket\.io|herokuapp\.com|azurewebsites\.net|cloudapp\.net|trafficmanager\.net|azurefd\.net|windows\.net|cloudfront\.net|netlify\.app|vercel\.app|surge\.sh|onrender\.com|fly\.dev|railway\.app|pythonanywhere\.com|wpengine\.com|pantheonsite\.io|wordpress\.com|myshopify\.com|tumblr\.com|ghost\.io|webflow\.io|readthedocs\.io|pages\.dev|workers\.dev|web\.app|firebaseapp\.com|strikingly\.com|tilda\.ws|zendesk\.com|freshdesk\.com|helpjuice\.com|unbouncepages\.com|cargo\.site|squarespace\.com|wixsite\.com)$')
                    THEN 'MEDIUM'
                WHEN regexp_matches(path, '(/api/jobs/|/api/generate|/api/tags|mlflow|/langflow|/flowise|/comfyui|/api/v4/|/(jenkins|teamcity|bamboo)/|/(portainer|harbor)/api/|/rancher/v3|/(zabbix|nagios|centreon|prometheus|grafana)/|/kibana/|/(artifactory|nexus)/|/phpmyadmin/|/_cat/|_all_dbs|/v[12]/keys/|/terminals/|/wd/hub/|/druid/|/cacti/|/solr/|/jmx-console|/web-console/|/invoker/|^/(script|scripttext)$|/console/(login|jndi)|/_async/|/goanywhere/|/webinterface/|/setup/setup-|/swagger|/openapi|/graphiql|/elmah|/trace\.axd|/server-status|/server-info|\.ds_store$|/nifi-api/|/airflow/|/api/v1/dags)')
                    THEN 'MEDIUM'
                -- LOW: generische Endpunkte, Client-Libs, Debug-Infos
                ELSE 'LOW'
            END AS confidence,

            -- =================================================================
            -- 3. Dynamische Nuclei-Tag-Generierung fuer zielgerichtete Scans
            -- =================================================================
            CASE
                WHEN fetch_status = 404 AND regexp_matches(host, '(amazonaws\.com|github\.io|gitlab\.io|bitbucket\.io|herokuapp\.com|azurewebsites\.net|cloudapp\.net|cloudfront\.net|netlify\.app|vercel\.app|wordpress\.com|myshopify\.com|tumblr\.com|zendesk\.com|freshdesk\.com|webflow\.io|ghost\.io|surge\.sh|fly\.dev|onrender\.com)$')
                    THEN 'takeover,dns,subdomain'
                WHEN regexp_matches(path, 'app/rest') THEN 'teamcity,auth-bypass,cve-2024-27198,rce'
                WHEN regexp_matches(path, 'geoserver') THEN 'geoserver,cve-2024-36401,rce'
                WHEN regexp_matches(path, '(jolokia|activemq|:8161)') THEN 'activemq,jolokia,cve-2023-46604,rce'
                WHEN regexp_matches(path, '/api/v1/totp') THEN 'ivanti,cve-2023-46805,cve-2024-21887,rce'
                WHEN regexp_matches(path, 'setupadministrator') THEN 'confluence,cve-2023-22515,cve-2023-22527,rce'
                WHEN regexp_matches(path, '/mgmt/tm/') THEN 'f5,cve-2022-1388,rce'
                WHEN regexp_matches(path, '/manager/(html|text)') THEN 'tomcat,manager,rce'
                WHEN regexp_matches(path, '(jmx-console|invoker)') THEN 'jboss,rce,unauth'
                WHEN regexp_matches(path, '^/(script|scripttext)$') THEN 'jenkins,script-console,rce'
                WHEN regexp_matches(path, '(wls-wsat|/console/)') THEN 'weblogic,cve-2020-14882,rce'
                WHEN regexp_matches(path, '/solr/') THEN 'solr,cve-2019-17558,rce'
                WHEN regexp_matches(path, 'eval-stdin\.php') THEN 'phpunit,cve-2017-9841,rce'
                WHEN regexp_matches(path, '_ignition') THEN 'laravel,ignition,cve-2021-3129,rce'
                WHEN regexp_matches(path, '(autodiscover|/ews/|/ecp/)') THEN 'exchange,proxylogon,proxyshell,rce'
                WHEN regexp_matches(path, 'vropspluginui') THEN 'vmware,vcenter,cve-2021-21972,rce'
                WHEN regexp_matches(path, '(/remote/fgt_lang|sslvpn)') THEN 'fortinet,cve-2024-21762,rce'
                WHEN regexp_matches(path, 'global-protect') THEN 'panos,cve-2024-3400,rce'
                WHEN regexp_matches(path, '/cacti/') THEN 'cacti,cve-2022-46169,rce'
                WHEN regexp_matches(path, '/cfide/') THEN 'coldfusion,cve-2023-26360,rce'
                WHEN regexp_matches(path, '(/service/soap|zimbra)') THEN 'zimbra,cve-2024-45519,rce'
                WHEN regexp_matches(path, '/goanywhere/') THEN 'goanywhere,cve-2023-0669,rce'
                WHEN regexp_matches(path, 'moveit') THEN 'moveit,cve-2023-34362,sqli,rce'
                WHEN regexp_matches(path, '/webinterface/') THEN 'crushftp,cve-2025-31161,rce'
                WHEN regexp_matches(path, '(/mifs/|/rs/api/v2/)') THEN 'ivanti,epmm,cve-2023-35082,rce'
                WHEN regexp_matches(path, '/minio/bootstrap') THEN 'minio,cve-2023-28432,exposure'
                WHEN regexp_matches(path, '/nacos/') THEN 'nacos,unauth,rce'
                WHEN regexp_matches(path, '/apisix/') THEN 'apisix,cve-2022-24112,rce'
                WHEN regexp_matches(path, '(_cat|_all_dbs)') THEN 'elasticsearch,couchdb,unauth,exposure'
                WHEN regexp_matches(path, '/v[12]/keys/') THEN 'etcd,unauth,exposure'
                WHEN regexp_matches(path, '/terminals/') THEN 'jupyter,unauth,rce'
                WHEN regexp_matches(path, '/wd/hub/') THEN 'selenium,grid,unauth,rce'
                WHEN regexp_matches(path, '/druid/') THEN 'druid,cve-2021-25646,rce'
                WHEN regexp_matches(path, '/sdk/weblanguage') THEN 'hikvision,cve-2021-36260,rce'
                WHEN regexp_matches(path, 'validate/code') THEN 'langflow,cve-2025-3248,rce'
                WHEN regexp_matches(path, '(ray|mlflow|ollama|/api/generate|/api/jobs|/v1/models|/comfyui|/flowise|/langflow)') THEN 'ray,mlflow,ai,rce,unauth'
                WHEN regexp_matches(path, '/actuator/') THEN 'springboot,actuator,exposure,rce'
                WHEN regexp_matches(path, '(nifi|airflow)') THEN 'nifi,airflow,rce,unauth'
                WHEN regexp_matches(path, 'oauth/idp') THEN 'citrix,cve-2023-4966,exposure'
                WHEN regexp_matches(path, '/api/v4/') THEN 'gitlab,exposure,api'
                WHEN regexp_matches(path, '(jenkins|teamcity|bamboo)') THEN 'cicd,jenkins,teamcity,exposure'
                WHEN regexp_matches(path, '(portainer|rancher|harbor)') THEN 'docker,k8s,registry,exposure'
                WHEN regexp_matches(path, '(zabbix|nagios|centreon|prometheus|grafana|kibana)') THEN 'monitoring,exposure'
                WHEN regexp_matches(path, '\.env') THEN 'exposure,env,secrets'
                WHEN regexp_matches(path, '/\.git/') THEN 'exposure,git,source'
                WHEN regexp_matches(path, '(id_rsa|id_ed25519|credentials)') THEN 'exposure,keys,ssh'
                WHEN regexp_matches(path, '\.(tfstate|tfvars)|postman') THEN 'exposure,secrets,terraform'
                WHEN regexp_matches(path, '(settings\.php|wp-config)') THEN 'exposure,cms,config'
                WHEN regexp_matches(path, '\.(sql|dump|zip|tar\.gz)') THEN 'backup,exposure,database'
                WHEN regexp_matches(path, '\.map$') THEN 'sourcemap,exposure'
                WHEN regexp_matches(path, '(phpinfo|elmah|trace\.axd|server-status)') THEN 'exposure,debug'
                WHEN regexp_matches(path, '(swagger|openapi|graphiql|graphql)') THEN 'api,exposure,graphql'
                WHEN regexp_matches(path, 'polyfill') THEN 'supply-chain,xss'
                WHEN regexp_matches(path, 'pdf(\.min)?\.js') THEN 'cve,cve-2024-4367,xss'
                WHEN regexp_matches(path, 'angular') THEN 'csti,xss'
                WHEN regexp_matches(path, 'jquery') THEN 'xss,cve-2020-11022'
                WHEN regexp_matches(path, 'lodash') THEN 'proto-pollution'
                ELSE 'cve,exposure,misconfig'
            END AS nuclei_tags
        FROM prefiltered_assets
    )
    SELECT
        url_host_registered_domain,
        url_host_name,
        url,
        fetch_status,
        vulnerability_class,
        confidence,
        nuclei_tags
    FROM classified
    WHERE vulnerability_class <> 'OTHER_TARGET_ENDPOINT'
      -- Nachfilter gegen False Positives:
      -- 1. 404-Treffer sind nur fuer Takeover-Kandidaten relevant
      --    (eine 404-.env ist KEIN Leak - die Datei existiert nicht)
      AND (fetch_status <> 404 OR vulnerability_class LIKE 'TAKEOVER_%')
      -- 2. Statische Assets (Bilder/Fonts/Videos) koennen keine Server-RCEs/Leaks sein
      AND NOT regexp_matches(path, '\.(png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|otf|eot|mp[34]|webm|mov|avi|flv|mkv|css|less|scss|ics)$')
      -- 3. Client-Lib-Treffer nur bei erkannter verwundbarer Version im Pfad
      AND (
          vulnerability_class NOT LIKE 'CLIENT_%'
          OR regexp_matches(path, '[0-9]+\.[0-9]+')
      )
      -- 4. Code-Hosting-Plattformen: deren /migrations/*.sql, Test-Keys & Configs
      --    sind per Definition oeffentlicher Source-Code => kein Leak des Betreibers
      AND NOT regexp_matches(host, '(googlesource\.com|github\.com|githubusercontent\.com|gitlab\.com|bitbucket\.org|sourceforge\.net|gitee\.com|gitcode\.com|codeberg\.org|sr\.ht|gitbook\.io)$')
      -- 5. SQL-Migrations-Dateien in Repos sind Source-Code, keine DB-Dumps
      AND NOT (vulnerability_class = 'LEAK_DATABASE_OR_FULL_BACKUP' AND regexp_matches(path, '/migrations?/'))
) TO 'all_vulnerabilities_master.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);
