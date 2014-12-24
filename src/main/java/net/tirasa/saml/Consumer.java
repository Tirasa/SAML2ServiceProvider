/* 
 * Copyright 2014 Expression project.organization is undefined on line 4, column 57 in unknown..
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

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.tirasa.saml.store.SAMLSessionManager;
import net.tirasa.saml.util.SAMLUtils;
import org.opensaml.common.binding.SAMLMessageContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author fabio
 */
public class Consumer extends HttpServlet {

    private static Logger log = LoggerFactory.getLogger(Consumer.class);
    
    private final static String SAML_AUTHN_RESPONSE_PARAMETER_NAME = "SAMLResponse";

    private static final long serialVersionUID = 1L;
    
    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code> methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        log.debug("Attempt to secure resource  is intercepted : {}", ((HttpServletRequest) request).
                getRequestURL().toString());
        
        /*
         * Check if response message is received from identity provider;
         * In case of successful response system redirects user to relayState (initial) request
         */
        String responseMessage = request.getParameter(SAML_AUTHN_RESPONSE_PARAMETER_NAME);
        if (responseMessage != null) {
            log.debug("Response from Identity Provider is received");
            try {
                log.debug("Decoding of SAML message");
                SAMLMessageContext samlMessageContext = SAMLUtils.decodeSamlMessage(request, response);
                
                log.debug("SAML message has been decoded successfully");
                
                samlMessageContext.setLocalEntityId("http://localhost:9080/");

                String relayState = samlMessageContext.getRelayState();

                new SAMLResponseVerifier().verify(samlMessageContext);
                
                log.debug("Starting and store SAML session..");
                SAMLSessionManager.getInstance().createSAMLSession(request.getSession(),
                        samlMessageContext);
                
                log.debug("User has been successfully authenticated in idP. "
                        + "Redirect to initial requested resource {}", relayState);

                response.sendRedirect(relayState);
                return;
            } catch (Exception e) {
                e.printStackTrace();
                throw new ServletException(e);
            }
        }

//        if (getCorrectURL(request).equals(filterConfig.getLogoutUrl())) {
//            log.debug("Logout action: destroying SAML session.");
//            SAMLSessionManager.getInstance().destroySAMLSession(request.getSession());
//            chain.doFilter(request, response);
//            return;
//        }
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
