/* 
 * Copyright 2015 Tirasa.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.saml;

import static net.tirasa.saml.store.SAMLSessionManager.SAML_SESSION_INFO;

import java.io.IOException;
import java.rmi.ServerException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import net.tirasa.saml.context.COT;
import net.tirasa.saml.context.IdP;
import net.tirasa.saml.store.SAMLSessionInfo;
import net.tirasa.saml.store.SAMLSessionManager;
import net.tirasa.saml.util.Constants;
import net.tirasa.saml.util.Properties;
import net.tirasa.saml.util.SAMLUtils;
import org.apache.commons.lang.StringUtils;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author fabio
 */
public class Consumer extends HttpServlet {

    private static final long serialVersionUID = 1L;

    private static final Logger log = LoggerFactory.getLogger(Consumer.class);

    /**
     * Processes AuthNResponses and LogoutRequests only.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        final String responseMessage = request.getParameter(Constants.SAML_AUTHN_RESPONSE_PARAMETER_NAME);
        final String requestMessage = request.getParameter(Constants.SAML_AUTHN_REQUEST_PARAMETER_NAME);

        if (StringUtils.isNotBlank(responseMessage)) {
            log.debug("Check for SSO response: {}", responseMessage);
            ssoResonse(request, response);
        } else if (StringUtils.isNotBlank(requestMessage)) {
            log.debug("Check for SLO request: {}", requestMessage);
            sloRequest(request, response);
        } else {
            log.warn("Received empty message");
            throw new ServerException("Received message is invalid");
        }
    }

    private void sloRequest(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {

        log.debug("Logout attempt: {}", request.getRequestURL().toString());

        try {
            final SAMLMessageContext<Response, SAMLObject, NameID> samlMessageContext = getSAMLMessageContext(
                    request, response);

            samlMessageContext.setLocalEntityId(
                    Properties.getString(Constants.ENTITYID, request.getRequestURL().toString()));

            final LogoutRequest inbound = LogoutRequest.class.cast(samlMessageContext.getInboundMessage());
            final IdP idp = COT.getInstance().getIdP(samlMessageContext.getInboundMessageIssuer());

            final HttpSession session = request.getSession();
            if (SAMLSessionManager.getInstance().isSAMLSessionValid(session)) {

                final Object info = session.getAttribute(SAML_SESSION_INFO);

                if (info == null) {
                    throw new Exception("Session info not found");
                }

                final SAMLSessionInfo sessionInfo = SAMLSessionInfo.class.cast(info);
                log.debug("Session info: " + sessionInfo);

                log.debug("Logout action: destroying SAML session.");
                SAMLSessionManager.getInstance().destroySAMLSession(session);

                log.info("Send SLO response to {}", idp.getId());
                new SAMLResponseSender().sendLogoutResponse(
                        request,
                        response,
                        idp,
                        inbound.getID());
            }

        } catch (Exception e) {
            log.warn("Received an invalid SAML2.0 message", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private void ssoResonse(final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException, IOException {

        log.debug("Attempt to secure resource  is intercepted : {}", request.getRequestURL().toString());

        /*
         * Check if response message is received from identity provider;
         * In case of successful response system redirects user to relayState (initial) request
         */
        try {

            final SAMLMessageContext<Response, SAMLObject, NameID> samlMessageContext = getSAMLMessageContext(request,
                    response);

            samlMessageContext.setLocalEntityId(
                    Properties.getString(Constants.ENTITYID, request.getRequestURL().toString()));

            final String relayState = samlMessageContext.getRelayState();

            new SAMLResponseVerifier().verify(samlMessageContext);

            log.debug("Starting and store SAML session..");
            SAMLSessionManager.getInstance().createSAMLSession(request.getSession(), samlMessageContext);

            log.debug("User has been successfully authenticated in idP. Redirect to initial requested resource {}",
                    relayState);

            response.sendRedirect(relayState);
        } catch (SAMLException | IOException e) {
            log.error("Error processing IdP response", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

    }

    private SAMLMessageContext<Response, SAMLObject, NameID> getSAMLMessageContext(
            final HttpServletRequest request, final HttpServletResponse response)
            throws ServletException {
        try {
            log.debug("Decoding of SAML message");
            final SAMLMessageContext<Response, SAMLObject, NameID> msg = SAMLUtils.decodeSamlMessage(request, response);
            log.debug("Received SAML message:\n{}", SAMLUtils.SAMLObjectToString(msg.getInboundMessage()));
            return msg;
        } catch (Exception e) {
            log.warn("Received an invalid SAML2.0 message");
            throw new ServletException("Received message is invalid", e);
        }

    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
