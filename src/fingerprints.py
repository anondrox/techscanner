FINGERPRINTS = {
    "javascript_frameworks": {
        "React": {
            "patterns": [
                {"type": "script", "pattern": r"react(?:\.min)?\.js"},
                {"type": "script", "pattern": r"react-dom(?:\.min)?\.js"},
                {"type": "html", "pattern": r"data-reactroot"},
                {"type": "html", "pattern": r"data-reactid"},
                {"type": "html", "pattern": r"__NEXT_DATA__"},
                {"type": "script_content", "pattern": r"React\.createElement"},
                {"type": "script_content", "pattern": r"_react\.default\.createElement"},
            ],
            "category": "JavaScript Framework",
            "website": "https://reactjs.org"
        },
        "Vue.js": {
            "patterns": [
                {"type": "script", "pattern": r"vue(?:\.min)?\.js"},
                {"type": "script", "pattern": r"vue\.runtime(?:\.min)?\.js"},
                {"type": "html", "pattern": r"data-v-[a-f0-9]+"},
                {"type": "html", "pattern": r"v-cloak"},
                {"type": "html", "pattern": r"v-if|v-for|v-bind|v-model"},
                {"type": "script_content", "pattern": r"Vue\.component"},
                {"type": "script_content", "pattern": r"new Vue\("},
            ],
            "category": "JavaScript Framework",
            "website": "https://vuejs.org"
        },
        "Angular": {
            "patterns": [
                {"type": "script", "pattern": r"angular(?:\.min)?\.js"},
                {"type": "html", "pattern": r"ng-app"},
                {"type": "html", "pattern": r"ng-controller"},
                {"type": "html", "pattern": r"ng-model"},
                {"type": "html", "pattern": r"\[ngClass\]|\[ngStyle\]"},
                {"type": "html", "pattern": r"_ngcontent-"},
                {"type": "html", "pattern": r"ng-version"},
            ],
            "category": "JavaScript Framework",
            "website": "https://angular.io"
        },
        "jQuery": {
            "patterns": [
                {"type": "script", "pattern": r"jquery(?:\.min)?\.js"},
                {"type": "script", "pattern": r"jquery-\d+\.\d+(?:\.\d+)?(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"\$\(document\)\.ready"},
                {"type": "script_content", "pattern": r"jQuery\.fn\."},
            ],
            "category": "JavaScript Library",
            "website": "https://jquery.com"
        },
        "Next.js": {
            "patterns": [
                {"type": "html", "pattern": r"__NEXT_DATA__"},
                {"type": "script", "pattern": r"_next/static"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"Next\.js"},
            ],
            "category": "JavaScript Framework",
            "website": "https://nextjs.org"
        },
        "Nuxt.js": {
            "patterns": [
                {"type": "html", "pattern": r"__NUXT__"},
                {"type": "script", "pattern": r"_nuxt/"},
                {"type": "html", "pattern": r"data-n-head"},
            ],
            "category": "JavaScript Framework",
            "website": "https://nuxtjs.org"
        },
        "Svelte": {
            "patterns": [
                {"type": "html", "pattern": r"svelte-"},
                {"type": "script", "pattern": r"svelte(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"SvelteComponent"},
            ],
            "category": "JavaScript Framework",
            "website": "https://svelte.dev"
        },
        "Ember.js": {
            "patterns": [
                {"type": "script", "pattern": r"ember(?:\.min)?\.js"},
                {"type": "html", "pattern": r"data-ember-action"},
                {"type": "html", "pattern": r"ember-view"},
            ],
            "category": "JavaScript Framework",
            "website": "https://emberjs.com"
        },
        "Backbone.js": {
            "patterns": [
                {"type": "script", "pattern": r"backbone(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"Backbone\.Model"},
            ],
            "category": "JavaScript Framework",
            "website": "https://backbonejs.org"
        },
        "Alpine.js": {
            "patterns": [
                {"type": "script", "pattern": r"alpine(?:\.min)?\.js"},
                {"type": "html", "pattern": r"x-data"},
                {"type": "html", "pattern": r"x-show|x-bind|x-on"},
            ],
            "category": "JavaScript Framework",
            "website": "https://alpinejs.dev"
        },
        "Preact": {
            "patterns": [
                {"type": "script", "pattern": r"preact(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"preact\.h\("},
            ],
            "category": "JavaScript Framework",
            "website": "https://preactjs.com"
        },
        "Stimulus": {
            "patterns": [
                {"type": "html", "pattern": r"data-controller"},
                {"type": "html", "pattern": r"data-action"},
                {"type": "script", "pattern": r"stimulus(?:\.min)?\.js"},
            ],
            "category": "JavaScript Framework",
            "website": "https://stimulus.hotwired.dev"
        },
        "HTMX": {
            "patterns": [
                {"type": "script", "pattern": r"htmx(?:\.min)?\.js"},
                {"type": "html", "pattern": r"hx-get|hx-post|hx-put|hx-delete"},
                {"type": "html", "pattern": r"hx-trigger|hx-swap"},
            ],
            "category": "JavaScript Library",
            "website": "https://htmx.org"
        },
        "Lodash": {
            "patterns": [
                {"type": "script", "pattern": r"lodash(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"_\.map\(|_\.filter\(|_\.reduce\("},
            ],
            "category": "JavaScript Library",
            "website": "https://lodash.com"
        },
        "Underscore.js": {
            "patterns": [
                {"type": "script", "pattern": r"underscore(?:\.min)?\.js"},
            ],
            "category": "JavaScript Library",
            "website": "https://underscorejs.org"
        },
        "Moment.js": {
            "patterns": [
                {"type": "script", "pattern": r"moment(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"moment\(\)\.format"},
            ],
            "category": "JavaScript Library",
            "website": "https://momentjs.com"
        },
        "D3.js": {
            "patterns": [
                {"type": "script", "pattern": r"d3(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"d3\.select"},
            ],
            "category": "JavaScript Library",
            "website": "https://d3js.org"
        },
        "Three.js": {
            "patterns": [
                {"type": "script", "pattern": r"three(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"THREE\.Scene"},
            ],
            "category": "JavaScript Library",
            "website": "https://threejs.org"
        },
        "Chart.js": {
            "patterns": [
                {"type": "script", "pattern": r"chart(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"new Chart\("},
            ],
            "category": "JavaScript Library",
            "website": "https://www.chartjs.org"
        },
        "Axios": {
            "patterns": [
                {"type": "script", "pattern": r"axios(?:\.min)?\.js"},
                {"type": "script_content", "pattern": r"axios\.get\(|axios\.post\("},
            ],
            "category": "JavaScript Library",
            "website": "https://axios-http.com"
        },
        "Handlebars.js": {
            "patterns": [
                {"type": "script", "pattern": r"handlebars(?:\.min)?\.js"},
                {"type": "script", "pattern": r"handlebars\.js/\d+\.\d+"},
                {"type": "script_content", "pattern": r"Handlebars\.compile"},
                {"type": "script_content", "pattern": r"Handlebars\.registerHelper"},
            ],
            "category": "JavaScript Library",
            "website": "https://handlebarsjs.com"
        },
        "CryptoJS": {
            "patterns": [
                {"type": "script", "pattern": r"crypto-js(?:\.min)?\.js"},
                {"type": "script", "pattern": r"crypto-js/\d+\.\d+"},
                {"type": "script_content", "pattern": r"CryptoJS\."},
                {"type": "script_content", "pattern": r"CryptoJS\.AES|CryptoJS\.SHA256|CryptoJS\.MD5"},
            ],
            "category": "JavaScript Library",
            "website": "https://cryptojs.gitbook.io"
        },
    },
    "css_frameworks": {
        "Bootstrap": {
            "patterns": [
                {"type": "css", "pattern": r"bootstrap(?:\.min)?\.css"},
                {"type": "script", "pattern": r"bootstrap(?:\.bundle)?(?:\.min)?\.js"},
                {"type": "html", "pattern": r"class=\"[^\"]*(?:container|row|col-(?:xs|sm|md|lg|xl)-\d+)"},
                {"type": "html", "pattern": r"class=\"[^\"]*btn btn-"},
            ],
            "category": "CSS Framework",
            "website": "https://getbootstrap.com"
        },
        "Tailwind CSS": {
            "patterns": [
                {"type": "css", "pattern": r"tailwind(?:\.min)?\.css"},
                {"type": "html", "pattern": r"class=\"[^\"]*(?:flex|grid|p-\d+|m-\d+|text-(?:xs|sm|base|lg|xl)|bg-(?:gray|red|blue|green)-\d{2,3})"},
                {"type": "html", "pattern": r"class=\"[^\"]*(?:hover:|focus:|dark:|sm:|md:|lg:|xl:)"},
            ],
            "category": "CSS Framework",
            "website": "https://tailwindcss.com"
        },
        "Bulma": {
            "patterns": [
                {"type": "css", "pattern": r"bulma(?:\.min)?\.css"},
                {"type": "html", "pattern": r"class=\"[^\"]*(?:is-primary|is-link|is-info|is-success|is-warning|is-danger)"},
                {"type": "html", "pattern": r"class=\"[^\"]*(?:columns|column|hero|section)"},
            ],
            "category": "CSS Framework",
            "website": "https://bulma.io"
        },
        "Foundation": {
            "patterns": [
                {"type": "css", "pattern": r"foundation(?:\.min)?\.css"},
                {"type": "html", "pattern": r"class=\"[^\"]*(?:small-\d+|medium-\d+|large-\d+)"},
            ],
            "category": "CSS Framework",
            "website": "https://get.foundation"
        },
        "Materialize": {
            "patterns": [
                {"type": "css", "pattern": r"materialize(?:\.min)?\.css"},
                {"type": "html", "pattern": r"class=\"[^\"]*(?:waves-effect|waves-light|card-panel)"},
            ],
            "category": "CSS Framework",
            "website": "https://materializecss.com"
        },
        "Semantic UI": {
            "patterns": [
                {"type": "css", "pattern": r"semantic(?:\.min)?\.css"},
                {"type": "html", "pattern": r"class=\"ui (?:button|container|grid|menu|segment)"},
            ],
            "category": "CSS Framework",
            "website": "https://semantic-ui.com"
        },
        "Pure CSS": {
            "patterns": [
                {"type": "css", "pattern": r"pure(?:-min)?\.css"},
                {"type": "html", "pattern": r"class=\"pure-"},
            ],
            "category": "CSS Framework",
            "website": "https://purecss.io"
        },
        "UIKit": {
            "patterns": [
                {"type": "css", "pattern": r"uikit(?:\.min)?\.css"},
                {"type": "html", "pattern": r"class=\"uk-"},
                {"type": "html", "pattern": r"uk-grid|uk-navbar"},
            ],
            "category": "CSS Framework",
            "website": "https://getuikit.com"
        },
        "Chakra UI": {
            "patterns": [
                {"type": "html", "pattern": r"chakra-"},
                {"type": "script_content", "pattern": r"@chakra-ui"},
            ],
            "category": "CSS Framework",
            "website": "https://chakra-ui.com"
        },
        "Ant Design": {
            "patterns": [
                {"type": "css", "pattern": r"antd(?:\.min)?\.css"},
                {"type": "html", "pattern": r"class=\"ant-"},
            ],
            "category": "CSS Framework",
            "website": "https://ant.design"
        },
        "DaisyUI": {
            "patterns": [
                {"type": "html", "pattern": r"class=\"[^\"]*(?:btn-primary|card-body|navbar|drawer)"},
                {"type": "html", "pattern": r"data-theme="},
            ],
            "category": "CSS Framework",
            "website": "https://daisyui.com"
        },
    },
    "cms": {
        "WordPress": {
            "patterns": [
                {"type": "html", "pattern": r"wp-content/"},
                {"type": "html", "pattern": r"wp-includes/"},
                {"type": "meta", "pattern": r"generator", "value": r"WordPress"},
                {"type": "html", "pattern": r"wp-json"},
                {"type": "header", "pattern": r"link", "value": r"wp-json"},
            ],
            "category": "CMS",
            "website": "https://wordpress.org"
        },
        "Drupal": {
            "patterns": [
                {"type": "html", "pattern": r"Drupal\.settings"},
                {"type": "meta", "pattern": r"generator", "value": r"Drupal"},
                {"type": "html", "pattern": r"/sites/default/files/"},
                {"type": "header", "pattern": r"x-drupal-cache"},
                {"type": "header", "pattern": r"x-generator", "value": r"Drupal"},
            ],
            "category": "CMS",
            "website": "https://www.drupal.org"
        },
        "Joomla": {
            "patterns": [
                {"type": "html", "pattern": r"/media/jui/"},
                {"type": "meta", "pattern": r"generator", "value": r"Joomla"},
                {"type": "html", "pattern": r"option=com_"},
            ],
            "category": "CMS",
            "website": "https://www.joomla.org"
        },
        "Shopify": {
            "patterns": [
                {"type": "html", "pattern": r"cdn\.shopify\.com"},
                {"type": "html", "pattern": r"Shopify\.theme"},
                {"type": "header", "pattern": r"x-shopify-stage"},
                {"type": "script_content", "pattern": r"Shopify\."},
            ],
            "category": "E-commerce",
            "website": "https://www.shopify.com"
        },
        "Magento": {
            "patterns": [
                {"type": "html", "pattern": r"/static/version"},
                {"type": "html", "pattern": r"Magento_"},
                {"type": "html", "pattern": r"mage/cookies"},
                {"type": "script_content", "pattern": r"Mage\.Cookies"},
            ],
            "category": "E-commerce",
            "website": "https://magento.com"
        },
        "WooCommerce": {
            "patterns": [
                {"type": "html", "pattern": r"woocommerce"},
                {"type": "html", "pattern": r"wc-block-"},
                {"type": "script", "pattern": r"woocommerce"},
            ],
            "category": "E-commerce",
            "website": "https://woocommerce.com"
        },
        "Squarespace": {
            "patterns": [
                {"type": "html", "pattern": r"squarespace\.com"},
                {"type": "html", "pattern": r"static\.squarespace\.com"},
                {"type": "script_content", "pattern": r"Squarespace\."},
            ],
            "category": "CMS",
            "website": "https://www.squarespace.com"
        },
        "Wix": {
            "patterns": [
                {"type": "html", "pattern": r"wix\.com"},
                {"type": "html", "pattern": r"static\.wixstatic\.com"},
                {"type": "meta", "pattern": r"generator", "value": r"Wix"},
            ],
            "category": "CMS",
            "website": "https://www.wix.com"
        },
        "Ghost": {
            "patterns": [
                {"type": "meta", "pattern": r"generator", "value": r"Ghost"},
                {"type": "html", "pattern": r"ghost-"},
            ],
            "category": "CMS",
            "website": "https://ghost.org"
        },
        "Webflow": {
            "patterns": [
                {"type": "html", "pattern": r"webflow\.com"},
                {"type": "meta", "pattern": r"generator", "value": r"Webflow"},
                {"type": "html", "pattern": r"w-webflow-badge"},
            ],
            "category": "CMS",
            "website": "https://webflow.com"
        },
        "Hugo": {
            "patterns": [
                {"type": "meta", "pattern": r"generator", "value": r"Hugo"},
            ],
            "category": "Static Site Generator",
            "website": "https://gohugo.io"
        },
        "Jekyll": {
            "patterns": [
                {"type": "meta", "pattern": r"generator", "value": r"Jekyll"},
            ],
            "category": "Static Site Generator",
            "website": "https://jekyllrb.com"
        },
        "Gatsby": {
            "patterns": [
                {"type": "html", "pattern": r"gatsby-"},
                {"type": "meta", "pattern": r"generator", "value": r"Gatsby"},
                {"type": "script", "pattern": r"gatsby-"},
            ],
            "category": "Static Site Generator",
            "website": "https://www.gatsbyjs.com"
        },
        "Astro": {
            "patterns": [
                {"type": "meta", "pattern": r"generator", "value": r"Astro"},
                {"type": "html", "pattern": r"astro-"},
            ],
            "category": "Static Site Generator",
            "website": "https://astro.build"
        },
        "Eleventy": {
            "patterns": [
                {"type": "meta", "pattern": r"generator", "value": r"Eleventy"},
            ],
            "category": "Static Site Generator",
            "website": "https://www.11ty.dev"
        },
    },
    "server_technologies": {
        "Nginx": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"nginx"},
                {"type": "header", "pattern": r"x-nginx-cache"},
            ],
            "category": "Web Server",
            "website": "https://nginx.org"
        },
        "Apache": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"Apache"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"Apache"},
                {"type": "html", "pattern": r"Apache/\d+\.\d+"},
                {"type": "html", "pattern": r"apache_pb\.gif"},
                {"type": "html", "pattern": r"/icons/apache_pb"},
            ],
            "category": "Web Server",
            "website": "https://httpd.apache.org"
        },
        "Apache Tomcat": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"Apache-Coyote"},
                {"type": "header", "pattern": r"server", "value": r"Tomcat"},
                {"type": "html", "pattern": r"Apache Tomcat"},
                {"type": "html", "pattern": r"tomcat\.gif"},
                {"type": "html", "pattern": r"/manager/html"},
                {"type": "cookie", "pattern": r"JSESSIONID"},
                {"type": "url", "pattern": r"\.jsp"},
                {"type": "html", "pattern": r"org\.apache\.catalina"},
            ],
            "category": "Web Server",
            "website": "https://tomcat.apache.org"
        },
        "Microsoft IIS": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"Microsoft-IIS"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"ASP\.NET"},
                {"type": "header", "pattern": r"x-aspnet-version"},
                {"type": "html", "pattern": r"iisstart\.htm"},
                {"type": "html", "pattern": r"iis-\d+\.png"},
            ],
            "category": "Web Server",
            "website": "https://www.iis.net"
        },
        "Java": {
            "patterns": [
                {"type": "cookie", "pattern": r"JSESSIONID"},
                {"type": "url", "pattern": r"\.jsp"},
                {"type": "url", "pattern": r"\.do"},
                {"type": "url", "pattern": r"\.action"},
                {"type": "html", "pattern": r"java\.sun\.com"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"JSP"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"Java"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"Servlet"},
            ],
            "category": "Programming Language",
            "website": "https://www.java.com"
        },
        "JSP": {
            "patterns": [
                {"type": "url", "pattern": r"\.jsp"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"JSP"},
                {"type": "html", "pattern": r"<%@\s*page"},
                {"type": "html", "pattern": r"javax\.servlet"},
            ],
            "category": "Programming Language",
            "website": "https://www.oracle.com/java/technologies/jspt.html"
        },
        "JBoss": {
            "patterns": [
                {"type": "header", "pattern": r"x-powered-by", "value": r"JBoss"},
                {"type": "header", "pattern": r"server", "value": r"JBoss"},
                {"type": "html", "pattern": r"jboss\.org"},
            ],
            "category": "Application Server",
            "website": "https://www.redhat.com/en/technologies/jboss-middleware/application-platform"
        },
        "WebLogic": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"WebLogic"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"WebLogic"},
                {"type": "html", "pattern": r"WebLogic Server"},
            ],
            "category": "Application Server",
            "website": "https://www.oracle.com/middleware/weblogic/"
        },
        "WebSphere": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"WebSphere"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"Servlet"},
                {"type": "cookie", "pattern": r"JSESSIONID"},
            ],
            "category": "Application Server",
            "website": "https://www.ibm.com/products/websphere-application-server"
        },
        "GlassFish": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"GlassFish"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"GlassFish"},
            ],
            "category": "Application Server",
            "website": "https://glassfish.org"
        },
        "Jetty": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"Jetty"},
            ],
            "category": "Web Server",
            "website": "https://www.eclipse.org/jetty/"
        },
        "Express.js": {
            "patterns": [
                {"type": "header", "pattern": r"x-powered-by", "value": r"Express"},
            ],
            "category": "Backend Framework",
            "website": "https://expressjs.com"
        },
        "PHP": {
            "patterns": [
                {"type": "header", "pattern": r"x-powered-by", "value": r"PHP"},
                {"type": "url", "pattern": r"\.php"},
                {"type": "cookie", "pattern": r"PHPSESSID"},
                {"type": "html", "pattern": r"php\.net"},
            ],
            "category": "Programming Language",
            "website": "https://www.php.net"
        },
        "ASP.NET": {
            "patterns": [
                {"type": "header", "pattern": r"x-powered-by", "value": r"ASP\.NET"},
                {"type": "header", "pattern": r"x-aspnet-version"},
                {"type": "header", "pattern": r"x-aspnetmvc-version"},
                {"type": "url", "pattern": r"\.aspx"},
                {"type": "url", "pattern": r"\.asmx"},
                {"type": "url", "pattern": r"\.ashx"},
                {"type": "url", "pattern": r"\.axd"},
                {"type": "cookie", "pattern": r"ASP\.NET_SessionId"},
                {"type": "cookie", "pattern": r"\.ASPXAUTH"},
                {"type": "html", "pattern": r"__VIEWSTATE"},
                {"type": "html", "pattern": r"__EVENTVALIDATION"},
                {"type": "html", "pattern": r"WebResource\.axd"},
                {"type": "html", "pattern": r"ScriptResource\.axd"},
            ],
            "category": "Backend Framework",
            "website": "https://dotnet.microsoft.com/apps/aspnet"
        },
        "ASP Classic": {
            "patterns": [
                {"type": "url", "pattern": r"\.asp(?!\.)"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"ASP"},
            ],
            "category": "Programming Language",
            "website": "https://docs.microsoft.com/en-us/previous-versions/iis/6.0-sdk/ms524929(v=vs.90)"
        },
        "ColdFusion": {
            "patterns": [
                {"type": "url", "pattern": r"\.cfm"},
                {"type": "url", "pattern": r"\.cfc"},
                {"type": "cookie", "pattern": r"CFID"},
                {"type": "cookie", "pattern": r"CFTOKEN"},
                {"type": "header", "pattern": r"server", "value": r"ColdFusion"},
            ],
            "category": "Programming Language",
            "website": "https://www.adobe.com/products/coldfusion-family.html"
        },
        "Perl": {
            "patterns": [
                {"type": "url", "pattern": r"\.pl"},
                {"type": "url", "pattern": r"\.cgi"},
                {"type": "header", "pattern": r"server", "value": r"mod_perl"},
            ],
            "category": "Programming Language",
            "website": "https://www.perl.org"
        },
        "Python": {
            "patterns": [
                {"type": "url", "pattern": r"\.py"},
                {"type": "header", "pattern": r"server", "value": r"Python"},
                {"type": "header", "pattern": r"server", "value": r"gunicorn"},
                {"type": "header", "pattern": r"server", "value": r"Werkzeug"},
            ],
            "category": "Programming Language",
            "website": "https://www.python.org"
        },
        "Node.js": {
            "patterns": [
                {"type": "header", "pattern": r"x-powered-by", "value": r"Express"},
                {"type": "header", "pattern": r"x-powered-by", "value": r"Node"},
            ],
            "category": "Runtime",
            "website": "https://nodejs.org"
        },
        "OpenSSL": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"OpenSSL"},
            ],
            "category": "Security",
            "website": "https://www.openssl.org"
        },
        "mod_ssl": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"mod_ssl"},
            ],
            "category": "Security",
            "website": "https://httpd.apache.org/docs/current/mod/mod_ssl.html"
        },
        "LiteSpeed": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"LiteSpeed"},
            ],
            "category": "Web Server",
            "website": "https://www.litespeedtech.com"
        },
        "Caddy": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"Caddy"},
            ],
            "category": "Web Server",
            "website": "https://caddyserver.com"
        },
        "HAProxy": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"HAProxy"},
                {"type": "cookie", "pattern": r"SERVERID"},
            ],
            "category": "Load Balancer",
            "website": "http://www.haproxy.org"
        },
        "Django": {
            "patterns": [
                {"type": "html", "pattern": r"csrfmiddlewaretoken"},
                {"type": "header", "pattern": r"x-frame-options", "value": r"SAMEORIGIN"},
                {"type": "cookie", "pattern": r"csrftoken"},
            ],
            "category": "Backend Framework",
            "website": "https://www.djangoproject.com"
        },
        "Ruby on Rails": {
            "patterns": [
                {"type": "header", "pattern": r"x-powered-by", "value": r"Phusion Passenger"},
                {"type": "html", "pattern": r"csrf-token"},
                {"type": "header", "pattern": r"x-runtime"},
            ],
            "category": "Backend Framework",
            "website": "https://rubyonrails.org"
        },
        "Laravel": {
            "patterns": [
                {"type": "cookie", "pattern": r"laravel_session"},
                {"type": "html", "pattern": r"csrf-token"},
            ],
            "category": "Backend Framework",
            "website": "https://laravel.com"
        },
        "Flask": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"Werkzeug"},
            ],
            "category": "Backend Framework",
            "website": "https://flask.palletsprojects.com"
        },
        "FastAPI": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"uvicorn"},
            ],
            "category": "Backend Framework",
            "website": "https://fastapi.tiangolo.com"
        },
        "Spring": {
            "patterns": [
                {"type": "header", "pattern": r"x-application-context"},
            ],
            "category": "Backend Framework",
            "website": "https://spring.io"
        },
        "Cloudflare": {
            "patterns": [
                {"type": "header", "pattern": r"server", "value": r"cloudflare"},
                {"type": "header", "pattern": r"cf-ray"},
                {"type": "header", "pattern": r"cf-cache-status"},
            ],
            "category": "CDN",
            "website": "https://www.cloudflare.com"
        },
        "Amazon CloudFront": {
            "patterns": [
                {"type": "header", "pattern": r"x-amz-cf-id"},
                {"type": "header", "pattern": r"x-amz-cf-pop"},
            ],
            "category": "CDN",
            "website": "https://aws.amazon.com/cloudfront/"
        },
        "Fastly": {
            "patterns": [
                {"type": "header", "pattern": r"x-served-by", "value": r"cache-"},
                {"type": "header", "pattern": r"x-fastly-request-id"},
            ],
            "category": "CDN",
            "website": "https://www.fastly.com"
        },
        "Akamai": {
            "patterns": [
                {"type": "header", "pattern": r"x-akamai-"},
            ],
            "category": "CDN",
            "website": "https://www.akamai.com"
        },
        "Vercel": {
            "patterns": [
                {"type": "header", "pattern": r"x-vercel-id"},
                {"type": "header", "pattern": r"server", "value": r"Vercel"},
            ],
            "category": "Hosting",
            "website": "https://vercel.com"
        },
        "Netlify": {
            "patterns": [
                {"type": "header", "pattern": r"x-nf-request-id"},
                {"type": "header", "pattern": r"server", "value": r"Netlify"},
            ],
            "category": "Hosting",
            "website": "https://www.netlify.com"
        },
        "Heroku": {
            "patterns": [
                {"type": "header", "pattern": r"via", "value": r"heroku"},
            ],
            "category": "Hosting",
            "website": "https://www.heroku.com"
        },
        "AWS": {
            "patterns": [
                {"type": "header", "pattern": r"x-amzn-"},
                {"type": "header", "pattern": r"server", "value": r"AmazonS3"},
            ],
            "category": "Cloud Provider",
            "website": "https://aws.amazon.com"
        },
        "Google Cloud": {
            "patterns": [
                {"type": "header", "pattern": r"x-goog-"},
                {"type": "header", "pattern": r"server", "value": r"Google Frontend"},
            ],
            "category": "Cloud Provider",
            "website": "https://cloud.google.com"
        },
    },
    "analytics_marketing": {
        "Google Analytics": {
            "patterns": [
                {"type": "script", "pattern": r"google-analytics\.com/analytics\.js"},
                {"type": "script", "pattern": r"googletagmanager\.com/gtag"},
                {"type": "script", "pattern": r"www\.google-analytics\.com/ga\.js"},
                {"type": "script_content", "pattern": r"gtag\(|ga\("},
            ],
            "category": "Analytics",
            "website": "https://analytics.google.com"
        },
        "Google Tag Manager": {
            "patterns": [
                {"type": "script", "pattern": r"googletagmanager\.com/gtm\.js"},
                {"type": "html", "pattern": r"GTM-[A-Z0-9]+"},
            ],
            "category": "Tag Manager",
            "website": "https://tagmanager.google.com"
        },
        "Facebook Pixel": {
            "patterns": [
                {"type": "script", "pattern": r"connect\.facebook\.net"},
                {"type": "script_content", "pattern": r"fbq\("},
            ],
            "category": "Analytics",
            "website": "https://www.facebook.com/business/tools/meta-pixel"
        },
        "Hotjar": {
            "patterns": [
                {"type": "script", "pattern": r"static\.hotjar\.com"},
                {"type": "script_content", "pattern": r"hj\(|hjid"},
            ],
            "category": "Analytics",
            "website": "https://www.hotjar.com"
        },
        "Mixpanel": {
            "patterns": [
                {"type": "script", "pattern": r"cdn\.mxpnl\.com"},
                {"type": "script_content", "pattern": r"mixpanel\."},
            ],
            "category": "Analytics",
            "website": "https://mixpanel.com"
        },
        "Segment": {
            "patterns": [
                {"type": "script", "pattern": r"cdn\.segment\.com"},
                {"type": "script_content", "pattern": r"analytics\."},
            ],
            "category": "Analytics",
            "website": "https://segment.com"
        },
        "Amplitude": {
            "patterns": [
                {"type": "script", "pattern": r"cdn\.amplitude\.com"},
                {"type": "script_content", "pattern": r"amplitude\."},
            ],
            "category": "Analytics",
            "website": "https://amplitude.com"
        },
        "Heap": {
            "patterns": [
                {"type": "script", "pattern": r"heapanalytics\.com"},
                {"type": "script_content", "pattern": r"heap\."},
            ],
            "category": "Analytics",
            "website": "https://heap.io"
        },
        "Plausible": {
            "patterns": [
                {"type": "script", "pattern": r"plausible\.io"},
            ],
            "category": "Analytics",
            "website": "https://plausible.io"
        },
        "Matomo": {
            "patterns": [
                {"type": "script", "pattern": r"matomo\.js"},
                {"type": "script_content", "pattern": r"_paq\.push"},
            ],
            "category": "Analytics",
            "website": "https://matomo.org"
        },
        "HubSpot": {
            "patterns": [
                {"type": "script", "pattern": r"js\.hs-scripts\.com"},
                {"type": "script", "pattern": r"js\.hubspot\.com"},
            ],
            "category": "Marketing",
            "website": "https://www.hubspot.com"
        },
        "Mailchimp": {
            "patterns": [
                {"type": "script", "pattern": r"chimpstatic\.com"},
                {"type": "html", "pattern": r"mailchimp"},
            ],
            "category": "Marketing",
            "website": "https://mailchimp.com"
        },
        "Intercom": {
            "patterns": [
                {"type": "script", "pattern": r"widget\.intercom\.io"},
                {"type": "script_content", "pattern": r"Intercom\("},
            ],
            "category": "Customer Support",
            "website": "https://www.intercom.com"
        },
        "Drift": {
            "patterns": [
                {"type": "script", "pattern": r"js\.driftt\.com"},
            ],
            "category": "Customer Support",
            "website": "https://www.drift.com"
        },
        "Zendesk": {
            "patterns": [
                {"type": "script", "pattern": r"static\.zdassets\.com"},
                {"type": "html", "pattern": r"zendesk"},
            ],
            "category": "Customer Support",
            "website": "https://www.zendesk.com"
        },
        "Crisp": {
            "patterns": [
                {"type": "script", "pattern": r"client\.crisp\.chat"},
            ],
            "category": "Customer Support",
            "website": "https://crisp.chat"
        },
        "Tawk.to": {
            "patterns": [
                {"type": "script", "pattern": r"embed\.tawk\.to"},
            ],
            "category": "Customer Support",
            "website": "https://www.tawk.to"
        },
        "Freshdesk": {
            "patterns": [
                {"type": "script", "pattern": r"widget\.freshworks\.com"},
            ],
            "category": "Customer Support",
            "website": "https://freshdesk.com"
        },
        "Olark": {
            "patterns": [
                {"type": "script", "pattern": r"static\.olark\.com"},
            ],
            "category": "Customer Support",
            "website": "https://www.olark.com"
        },
        "LiveChat": {
            "patterns": [
                {"type": "script", "pattern": r"cdn\.livechatinc\.com"},
            ],
            "category": "Customer Support",
            "website": "https://www.livechat.com"
        },
    },
    "fonts_icons": {
        "Google Fonts": {
            "patterns": [
                {"type": "css", "pattern": r"fonts\.googleapis\.com"},
                {"type": "css", "pattern": r"fonts\.gstatic\.com"},
            ],
            "category": "Fonts",
            "website": "https://fonts.google.com"
        },
        "Font Awesome": {
            "patterns": [
                {"type": "css", "pattern": r"font-awesome(?:\.min)?\.css"},
                {"type": "css", "pattern": r"fontawesome"},
                {"type": "html", "pattern": r"class=\"fa[rsb]? fa-"},
            ],
            "category": "Icons",
            "website": "https://fontawesome.com"
        },
        "Material Icons": {
            "patterns": [
                {"type": "css", "pattern": r"fonts\.googleapis\.com/icon"},
                {"type": "html", "pattern": r"class=\"material-icons"},
            ],
            "category": "Icons",
            "website": "https://fonts.google.com/icons"
        },
        "Ionicons": {
            "patterns": [
                {"type": "script", "pattern": r"ionicons"},
                {"type": "html", "pattern": r"ion-icon"},
            ],
            "category": "Icons",
            "website": "https://ionic.io/ionicons"
        },
        "Feather Icons": {
            "patterns": [
                {"type": "script", "pattern": r"feather(?:\.min)?\.js"},
                {"type": "html", "pattern": r"data-feather"},
            ],
            "category": "Icons",
            "website": "https://feathericons.com"
        },
        "Heroicons": {
            "patterns": [
                {"type": "html", "pattern": r"heroicon"},
            ],
            "category": "Icons",
            "website": "https://heroicons.com"
        },
        "Bootstrap Icons": {
            "patterns": [
                {"type": "css", "pattern": r"bootstrap-icons"},
                {"type": "html", "pattern": r"class=\"bi bi-"},
            ],
            "category": "Icons",
            "website": "https://icons.getbootstrap.com"
        },
        "Adobe Fonts": {
            "patterns": [
                {"type": "css", "pattern": r"use\.typekit\.net"},
            ],
            "category": "Fonts",
            "website": "https://fonts.adobe.com"
        },
    },
    "payment": {
        "Stripe": {
            "patterns": [
                {"type": "script", "pattern": r"js\.stripe\.com"},
                {"type": "script_content", "pattern": r"Stripe\("},
            ],
            "category": "Payment",
            "website": "https://stripe.com"
        },
        "PayPal": {
            "patterns": [
                {"type": "script", "pattern": r"paypal\.com/sdk"},
                {"type": "html", "pattern": r"paypal"},
            ],
            "category": "Payment",
            "website": "https://www.paypal.com"
        },
        "Square": {
            "patterns": [
                {"type": "script", "pattern": r"squareup\.com"},
                {"type": "script", "pattern": r"square\.js"},
            ],
            "category": "Payment",
            "website": "https://squareup.com"
        },
        "Braintree": {
            "patterns": [
                {"type": "script", "pattern": r"braintree"},
            ],
            "category": "Payment",
            "website": "https://www.braintreepayments.com"
        },
        "Klarna": {
            "patterns": [
                {"type": "script", "pattern": r"klarna"},
            ],
            "category": "Payment",
            "website": "https://www.klarna.com"
        },
        "Affirm": {
            "patterns": [
                {"type": "script", "pattern": r"affirm\.com"},
            ],
            "category": "Payment",
            "website": "https://www.affirm.com"
        },
    },
    "security": {
        "reCAPTCHA": {
            "patterns": [
                {"type": "script", "pattern": r"google\.com/recaptcha"},
                {"type": "html", "pattern": r"g-recaptcha"},
            ],
            "category": "Security",
            "website": "https://www.google.com/recaptcha"
        },
        "hCaptcha": {
            "patterns": [
                {"type": "script", "pattern": r"hcaptcha\.com"},
                {"type": "html", "pattern": r"h-captcha"},
            ],
            "category": "Security",
            "website": "https://www.hcaptcha.com"
        },
        "Cloudflare Turnstile": {
            "patterns": [
                {"type": "script", "pattern": r"challenges\.cloudflare\.com/turnstile"},
            ],
            "category": "Security",
            "website": "https://www.cloudflare.com/products/turnstile/"
        },
    },
    "video_media": {
        "YouTube": {
            "patterns": [
                {"type": "html", "pattern": r"youtube\.com/embed"},
                {"type": "html", "pattern": r"youtube-nocookie\.com"},
                {"type": "script", "pattern": r"youtube\.com/iframe_api"},
            ],
            "category": "Video",
            "website": "https://www.youtube.com"
        },
        "Vimeo": {
            "patterns": [
                {"type": "html", "pattern": r"player\.vimeo\.com"},
                {"type": "script", "pattern": r"player\.vimeo\.com"},
            ],
            "category": "Video",
            "website": "https://vimeo.com"
        },
        "Wistia": {
            "patterns": [
                {"type": "script", "pattern": r"wistia\.com"},
                {"type": "html", "pattern": r"wistia_embed"},
            ],
            "category": "Video",
            "website": "https://wistia.com"
        },
        "JW Player": {
            "patterns": [
                {"type": "script", "pattern": r"jwplayer"},
            ],
            "category": "Video",
            "website": "https://www.jwplayer.com"
        },
        "Video.js": {
            "patterns": [
                {"type": "script", "pattern": r"video(?:\.min)?\.js"},
                {"type": "html", "pattern": r"video-js"},
            ],
            "category": "Video",
            "website": "https://videojs.com"
        },
    },
    "social": {
        "Facebook SDK": {
            "patterns": [
                {"type": "script", "pattern": r"connect\.facebook\.net"},
                {"type": "html", "pattern": r"fb-root"},
            ],
            "category": "Social",
            "website": "https://developers.facebook.com"
        },
        "Twitter Widgets": {
            "patterns": [
                {"type": "script", "pattern": r"platform\.twitter\.com"},
            ],
            "category": "Social",
            "website": "https://developer.twitter.com"
        },
        "LinkedIn SDK": {
            "patterns": [
                {"type": "script", "pattern": r"platform\.linkedin\.com"},
            ],
            "category": "Social",
            "website": "https://developer.linkedin.com"
        },
        "Pinterest SDK": {
            "patterns": [
                {"type": "script", "pattern": r"assets\.pinterest\.com"},
            ],
            "category": "Social",
            "website": "https://developers.pinterest.com"
        },
        "AddThis": {
            "patterns": [
                {"type": "script", "pattern": r"addthis\.com"},
            ],
            "category": "Social",
            "website": "https://www.addthis.com"
        },
        "ShareThis": {
            "patterns": [
                {"type": "script", "pattern": r"sharethis\.com"},
            ],
            "category": "Social",
            "website": "https://sharethis.com"
        },
    },
    "misc": {
        "PWA": {
            "patterns": [
                {"type": "html", "pattern": r"manifest\.json"},
                {"type": "meta", "pattern": r"apple-mobile-web-app-capable"},
                {"type": "html", "pattern": r"service-?worker"},
            ],
            "category": "Web Technology",
            "website": "https://web.dev/progressive-web-apps/"
        },
        "AMP": {
            "patterns": [
                {"type": "html", "pattern": r"<html[^>]*amp"},
                {"type": "script", "pattern": r"cdn\.ampproject\.org"},
            ],
            "category": "Web Technology",
            "website": "https://amp.dev"
        },
        "WebAssembly": {
            "patterns": [
                {"type": "script_content", "pattern": r"WebAssembly"},
                {"type": "script", "pattern": r"\.wasm"},
            ],
            "category": "Web Technology",
            "website": "https://webassembly.org"
        },
        "GraphQL": {
            "patterns": [
                {"type": "script_content", "pattern": r"graphql"},
                {"type": "url", "pattern": r"/graphql"},
            ],
            "category": "API",
            "website": "https://graphql.org"
        },
        "Socket.io": {
            "patterns": [
                {"type": "script", "pattern": r"socket\.io"},
            ],
            "category": "Web Technology",
            "website": "https://socket.io"
        },
        "webpack": {
            "patterns": [
                {"type": "script_content", "pattern": r"webpackJsonp"},
                {"type": "script", "pattern": r"webpack"},
            ],
            "category": "Build Tool",
            "website": "https://webpack.js.org"
        },
        "Vite": {
            "patterns": [
                {"type": "script", "pattern": r"@vite"},
                {"type": "script", "pattern": r"vite"},
            ],
            "category": "Build Tool",
            "website": "https://vitejs.dev"
        },
        "Parcel": {
            "patterns": [
                {"type": "script", "pattern": r"parcel"},
            ],
            "category": "Build Tool",
            "website": "https://parceljs.org"
        },
        "esbuild": {
            "patterns": [
                {"type": "script_content", "pattern": r"esbuild"},
            ],
            "category": "Build Tool",
            "website": "https://esbuild.github.io"
        },
        "Sentry": {
            "patterns": [
                {"type": "script", "pattern": r"sentry"},
                {"type": "script", "pattern": r"browser\.sentry-cdn\.com"},
            ],
            "category": "Error Tracking",
            "website": "https://sentry.io"
        },
        "LogRocket": {
            "patterns": [
                {"type": "script", "pattern": r"cdn\.logrocket\.io"},
            ],
            "category": "Error Tracking",
            "website": "https://logrocket.com"
        },
        "Bugsnag": {
            "patterns": [
                {"type": "script", "pattern": r"bugsnag"},
            ],
            "category": "Error Tracking",
            "website": "https://www.bugsnag.com"
        },
        "Rollbar": {
            "patterns": [
                {"type": "script", "pattern": r"rollbar"},
            ],
            "category": "Error Tracking",
            "website": "https://rollbar.com"
        },
    }
}

SECURITY_HEADERS = {
    "content-security-policy": {
        "name": "Content Security Policy (CSP)",
        "description": "Controls resources the browser is allowed to load",
        "importance": "high",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    },
    "strict-transport-security": {
        "name": "HTTP Strict Transport Security (HSTS)",
        "description": "Forces HTTPS connections",
        "importance": "high",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "description": "Prevents clickjacking attacks",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "description": "Prevents MIME type sniffing",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "description": "Enables browser XSS filtering (legacy)",
        "importance": "low",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "description": "Controls referrer information sent with requests",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "description": "Controls browser feature permissions",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
    },
    "cross-origin-embedder-policy": {
        "name": "Cross-Origin-Embedder-Policy (COEP)",
        "description": "Prevents loading cross-origin resources without permission",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy (COOP)",
        "description": "Isolates browsing context from cross-origin documents",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy (CORP)",
        "description": "Prevents other domains from reading resource responses",
        "importance": "medium",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
    },
}
