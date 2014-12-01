/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package net.tirasa.saml;

import net.tirasa.saml.util.SAMLUtils;
import net.tirasa.saml.store.SAMLSessionManager;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.common.binding.SAMLMessageContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAMLSPFilter implements Filter {

    private static Logger log = LoggerFactory.getLogger(SAMLSPFilter.class);

    private final static String SAML_AUTHN_RESPONSE_PARAMETER_NAME = "SAMLResponse";

    FilterConfig filterConfig;

    @Override
    public void doFilter(
            final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain chain)
            throws ServletException,
            IOException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (!isFilteredRequest(request)) {
            log.debug("According to {} configuration parameter request is ignored + {}",
                    new Object[] { FilterConfig.EXCLUDED_URL_PATTERN_PARAMETER, request.getRequestURI() });
            chain.doFilter(servletRequest, servletResponse);
            return;
        }

        log.debug("Attempt to secure resource  is intercepted : {}", ((HttpServletRequest) servletRequest).
                getRequestURL().toString());
        /*
         * Check if response message is received from identity provider;
         * In case of successful response system redirects user to relayState (initial) request
         */
        String responseMessage = servletRequest.getParameter(SAML_AUTHN_RESPONSE_PARAMETER_NAME);
        if (responseMessage != null) {
            log.debug("Response from Identity Provider is received");
            try {
                log.debug("Decoding of SAML message");
                SAMLMessageContext samlMessageContext = SAMLUtils.decodeSamlMessage((HttpServletRequest) servletRequest,
                        (HttpServletResponse) servletResponse);
                log.debug("SAML message has been decoded successfully");
                samlMessageContext.setLocalEntityId(filterConfig.getSpProviderId());

                String relayState = samlMessageContext.getRelayState();

                new SAMLResponseVerifier().verify(samlMessageContext);

                log.debug("Starting and store SAML session..");
                SAMLSessionManager.getInstance().createSAMLSession(request.getSession(),
                        samlMessageContext);
                log.debug("User has been successfully authenticated in idP. Redirect to initial requested resource {}",
                        relayState);

                response.sendRedirect(relayState);
                return;
            } catch (Exception e) {
                throw new ServletException(e);
            }
        }

        if (getCorrectURL(request).equals(filterConfig.getLogoutUrl())) {
            log.debug("Logout action: destroying SAML session.");
            SAMLSessionManager.getInstance().destroySAMLSession(request.getSession());
            chain.doFilter(request, response);
            return;
        }
    }

    @Override
    public void destroy() {
    }

    // We add method to the filter class that will check if the request needs to be handled
    private boolean isFilteredRequest(final HttpServletRequest request) {
        return !(filterConfig.getExcludedUrlPattern() != null
                && getCorrectURL(request).matches(filterConfig.getExcludedUrlPattern()));
    }
// Also add the auxiliary method for receiving the correct URL

    private String getCorrectURL(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        String requestUri = request.getRequestURI();
        int contextBeg = requestUri.indexOf(contextPath);
        int contextEnd = contextBeg + contextPath.length();
        String slash = "/";
        String url = (contextBeg < 0 || contextEnd == (requestUri.length() - 1))
                ? requestUri : requestUri.substring(contextEnd);
        if (!url.startsWith(slash)) {
            url = slash + url;
        }
        return url;
    }

    public void init(final javax.servlet.FilterConfig fc) throws ServletException {
        filterConfig = new FilterConfig(fc);
    }
}
