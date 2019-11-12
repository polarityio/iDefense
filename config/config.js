module.exports = {
  /**
   * Name of the integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @required
   */
  name: "iDefense",
  /**
   * The acronym that appears in the notification window when information from this integration
   * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
   * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
   * here will be carried forward into the notification window.
   *
   * @type String
   * @required
   */
  acronym: "iDEF",

  /**
   * Description for this integration which is displayed in the Polarity integrations user interface
   *
   * @type String
   * @optional
   */
  description: "iDefense Security Intelligence",
  entityTypes: ["IPv4", "domain", 'email', 'url', 'hash'],
  customTypes:[
        {
            key: 'cve',
            regex: /CVE-(1999|2\d{3})-(0\d{2}[1-9]|[1-9]\d{3,})/
        },
        {
            key: 'cpe',
            regex: /[aho](:[A-Za-z0-9\._\-~]*(:[A-Za-z0-9\._\-~]*(:[A-Za-z0-9\._\.\-~]*(:[A-Za-z0-9\._\-~]*(:[A-Za-z0-9\._\-~]*(:[A-Za-z0-9\._\-~]*)?)?)?)?))/
        }
    ],
  /**
   * An array of style files (css or less) that will be included for your integration. Any styles specified in
   * the below files can be used in your custom template.
   *
   * @type Array
   * @optional
   */
  styles: ["./styles/idefense.less"],
  /**
   * Provide custom component logic and template for rendering the integration details block.  If you do not
   * provide a custom template and/or component then the integration will display data as a table of key value
   * pairs.
   *
   * @type Object
   * @optional
   */
  block: {
    component: {
      file: "./components/block.js"
    },
    template: {
      file: "./templates/block.hbs"
    }
  },
  summary: {
    component: {
      file: "./components/summary.js"
    },
    template: {
      file: "./templates/summary.hbs"
    }
  },
  request: {
    // Provide the path to your certFile. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    cert: "",
    // Provide the path to your private key. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    key: "",
    // Provide the key passphrase if required.  Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    passphrase: "",
    // Provide the Certificate Authority. Leave an empty string to ignore this option.
    // Relative paths are relative to the integration's root directory
    ca: "",
    // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
    // the url parameter (by embedding the auth info in the uri)
    proxy: "",

    rejectUnauthorized: true
  },
  logging: {
    level: "info" //trace, debug, info, warn, error, fatal
  },
  /**
   * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
   * as an array of option objects.
   *
   * @type Array
   * @optional
   */
  options: [
    {
      key: "apiKey",
      name: "API Key",
      description: "iDefense API Key",
      default: "",
      type: "password",
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: "minScore",
      name: "Minimum Severity Score",
      description:
        "Minimum severity score to display in the Polarity overlay window (Scale of 1-5)",
      default: 1,
      type: "number",
      userCanEdit: true,
      adminOnly: false
    },
    {
      key: "pageSize",
      name: "Number of Results",
      description:
        "Number of iDefense results to return about an associated indicator",
      default: 10,
      type: "number",
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: "blacklist",
      name: "Blacklist Domains or Ips",
      description:
        "List of domains or Ips that you never want to send to iDefense",
      default: "",
      type: "text",
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: "domainBlacklistRegex",
      name: "Domain Black List Regex",
      description:
        "Domains that match the given regex will not be looked up (if blank, no domains will be black listed)",
      default: "",
      type: "text",
      userCanEdit: false,
      adminOnly: false
    },
    {
      key: "ipBlacklistRegex",
      name: "IP Black List Regex",
      description:
        "IPs that match the given regex will not be looked up (if blank, no IPs will be black listed)",
      default: "",
      type: "text",
      userCanEdit: false,
      adminOnly: false
    }
  ]
};
