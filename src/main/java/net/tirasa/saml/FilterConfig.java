package net.tirasa.saml;

public class FilterConfig {

    /**
     * The parameters below should be defined in web.xml file of Java Web Application
     */
    public static final String EXCLUDED_URL_PATTERN_PARAMETER = "excludedUrlPattern";

    public static final String SP_ACS_URL_PARAMETER = "acsUrl";

    public static final String SP_ID_PARAMETER = "spProviderId";

    public static final String SP_LOGOUT_URL_PARAMETER = "logoutUrl";

    public static final String IDP_SSO_URL_PARAMETER = "idProviderSSOUrl";

    private String excludedUrlPattern;

    private String acsUrl;

    private String spProviderId;

    private String logoutUrl;

    private String idpSSOUrl;

    public FilterConfig(final javax.servlet.FilterConfig config) {
        excludedUrlPattern = config.getInitParameter(EXCLUDED_URL_PATTERN_PARAMETER);
        acsUrl = config.getInitParameter(SP_ACS_URL_PARAMETER);
        spProviderId = config.getInitParameter(SP_ID_PARAMETER);
        idpSSOUrl = config.getInitParameter(IDP_SSO_URL_PARAMETER);
        logoutUrl = config.getInitParameter(SP_LOGOUT_URL_PARAMETER);
    }

    public String getExcludedUrlPattern() {
        return excludedUrlPattern;
    }

    public String getAcsUrl() {
        return acsUrl;
    }

    public String getSpProviderId() {
        return spProviderId;
    }

    public String getLogoutUrl() {
        return logoutUrl;
    }

    public String getIdpSSOUrl() {
        return idpSSOUrl;
    }
}
