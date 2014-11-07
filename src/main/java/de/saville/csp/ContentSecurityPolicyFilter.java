package de.saville.csp;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adds the 'Content-Security-Policy' or 'Content-Security-Policy-Report-Only' Header to the response.
 *
 * Also see: http://content-security-policy.com/ & http://www.w3.org/TR/CSP/#directives
 *
 * Normally you will only need a limited number or none of the init parameters. If no init parameter is defined the Header will look like this:
 *
 *     Content-Security-Policy = default-src 'none'
 *
 * Here is an example full configuration of the ContentSecurityPolicyFilter.
 *
 *     <filter>
 *            <filter-name>ContentSecurityPolicyFilter</filter-name>
 *            <filter-class>de.saville.csp.ContentSecurityPolicyFilter</filter-class>
 *
 *            <init-param>
 *                <!-- If not specified the default is false -->
 *                <param-name>report-only</param-name>
 *                <param-value>false</param-value>
 *             </init-param>
 *            <!-- Optionally add a reporter-uri -->
 *            <init-param>
 *                <param-name>report-uri</param-name>
 *                <param-value>/ContentSecurityPolicyReporter</param-value>
 *             </init-param>
 *            <init-param>
 *                <param-name>sandbox</param-name>
 *                <param-value>true</param-value>
 *                <!-- true enables the sandbox behaviour - the default is false - one can also specify exceptions, e.g.
 *                <param-value>allow-forms allow-same-origin</param-value>
 *                -->
 *             </init-param>
 *            <!-- Remember that special keywords have to be put in single quotes, e.g. 'none', 'self' -->
 *            <init-param>
 *                <!-- If not specified the default is 'none' -->
 *                <param-name>default-src</param-name>
 *                <param-value>'none'</param-value>
 *             </init-param>
 *            <init-param>
 *                <param-name>img-src</param-name>
 *                 <param-value>http://*.example.com</param-value>
 *             </init-param>
 *            <init-param>
 *                <param-name>script-src</param-name>
 *                <param-value>'self' js.example.com</param-value>
 *             </init-param>
 *            <init-param>
 *                <param-name>style-src</param-name>
 *                <param-value>'self'</param-value>
 *             </init-param>
 *            <init-param>
 *                <param-name>connect-src</param-name>
 *                <param-value>'self'</param-value>
 *             </init-param>
 *            <init-param>
 *                <param-name>font-src</param-name>
 *                <param-value>'self'</param-value>
 *             </init-param>
 *            <init-param>
 *                <param-name>object-src</param-name>
 *                <param-value>'self'</param-value>
 *             </init-param>
 *            <init-param>
 *                <param-name>media-src</param-name>
 *                <param-value>'self'</param-value>
 *             </init-param>
 *            <init-param>
 *                <param-name>frame-src</param-name>
 *                <param-value>'self'</param-value>
 *             </init-param>
 *         </filter>
 *
 *         <filter-mapping>
 *            <filter-name>ContentSecurityPolicyFilter</filter-name>
 *             <url-pattern>/*</url-pattern>
 *         </filter-mapping>
 *
 *  @author Ronald Ploeger
 */
public class ContentSecurityPolicyFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(ContentSecurityPolicyFilter.class);
    public static final String CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";
    public static final String CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";

    /** Instruct the browser to only send reports (does not block anything) */
    private static final String REPORT_ONLY = "report-only";
    /** Instructs the browser to POST a reports of policy failures to this URI */
    public static final String REPORT_URI = "report-uri";
    /**
     * Enables a sandbox for the requested resource similar to the iframe sandbox attribute.
     * The sandbox applies a same origin policy, prevents popups, plugins and script execution is blocked.
     * You can keep the sandbox value empty to keep all restrictions in place, or add values:
     * allow-forms allow-same-origin allow-scripts, and allow-top-navigation
     */
    public static final String SANDBOX = "sandbox";
    /** The default policy for loading content such as JavaScript, Images, CSS, Font's, AJAX requests, Frames, HTML5 Media */
    public static final String DEFAULT_SRC = "default-src";
    /** Defines valid sources of images */
    public static final String IMG_SRC = "img-src";
    /** Defines valid sources of JavaScript  */
    public static final String SCRIPT_SRC = "script-src";
    /** Defines valid sources of stylesheets */
    public static final String STYLE_SRC = "style-src";
    /** Defines valid sources of fonts */
    public static final String FONT_SRC = "font-src";
    /** Applies to XMLHttpRequest (AJAX), WebSocket or EventSource */
    public static final String CONNECT_SRC = "connect-src";
    /** Defines valid sources of plugins, eg <object>, <embed> or <applet>.  */
    public static final String OBJECT_SRC = "object-src";
    /** Defines valid sources of audio and video, eg HTML5 <audio>, <video> elements */
    public static final String MEDIA_SRC = "media-src";
    /** Defines valid sources for loading frames */
    public static final String FRAME_SRC = "frame-src";

    public static final String KEYWORD_NONE = "'none'";
    public static final String KEYWORD_SELF = "'self'";

    private boolean reportOnly;
    private String reportUri;
    private String sandbox;
    private String defaultSrc;
    private String imgSrc;
    private String scriptSrc;
    private String styleSrc;
    private String fontSrc;
    private String connectSrc;
    private String objectSrc;
    private String mediaSrc;
    private String frameSrc;

    public void init(FilterConfig filterConfig) {
        reportOnly = getParameterBooleanValue(filterConfig, REPORT_ONLY);
        reportUri = getParameterValue(filterConfig, REPORT_URI);
        sandbox = getParameterValue(filterConfig, SANDBOX);
        defaultSrc = getParameterValue(filterConfig, DEFAULT_SRC, KEYWORD_NONE);
        imgSrc = getParameterValue(filterConfig, IMG_SRC);
        scriptSrc = getParameterValue(filterConfig, SCRIPT_SRC);
        styleSrc = getParameterValue(filterConfig, STYLE_SRC);
        fontSrc = getParameterValue(filterConfig, FONT_SRC);
        connectSrc = getParameterValue(filterConfig, CONNECT_SRC);
        objectSrc = getParameterValue(filterConfig, OBJECT_SRC);
        mediaSrc = getParameterValue(filterConfig, MEDIA_SRC);
        frameSrc = getParameterValue(filterConfig, FRAME_SRC);
    }

    private String getParameterValue(FilterConfig filterConfig, String paramName, String defaultValue) {
        String value = filterConfig.getInitParameter(paramName);
        if (StringUtils.isBlank(value)) {
            value = defaultValue;
        }
        return value;
    }

    private String getParameterValue(FilterConfig filterConfig, String paramName) {
        return filterConfig.getInitParameter(paramName);
    }

    private boolean getParameterBooleanValue(FilterConfig filterConfig, String paramName) {
        return "true".equalsIgnoreCase(filterConfig.getInitParameter(paramName));
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String contentSecurityPolicyHeaderName = reportOnly ? CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER : CONTENT_SECURITY_POLICY_HEADER;
        String contentSecurityPolicy = getContentSecurityPolicy();

        logger.debug("Adding Header {} = {}", contentSecurityPolicyHeaderName, contentSecurityPolicy);
        httpResponse.addHeader(contentSecurityPolicyHeaderName, contentSecurityPolicy);

        chain.doFilter(request, response);
    }

    private String getContentSecurityPolicy() {
        StringBuilder contentSecurityPolicy = new StringBuilder(DEFAULT_SRC).append(" ").append(defaultSrc);

        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, IMG_SRC, imgSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, SCRIPT_SRC, scriptSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, STYLE_SRC, styleSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, FONT_SRC, fontSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, CONNECT_SRC, connectSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, OBJECT_SRC, objectSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, MEDIA_SRC, mediaSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, FRAME_SRC, frameSrc);
        addDirectiveToContentSecurityPolicy(contentSecurityPolicy, REPORT_URI, reportUri);
        addSandoxDirectiveToContentSecurityPolicy(contentSecurityPolicy, sandbox);

        return contentSecurityPolicy.toString();
    }

    private void addDirectiveToContentSecurityPolicy(StringBuilder contentSecurityPolicy, String directiveName, String value) {
        if (StringUtils.isNotBlank(value) && !defaultSrc.equals(value)) {
            contentSecurityPolicy.append("; ").append(directiveName).append(" ").append(value);
        }
    }

    private void addSandoxDirectiveToContentSecurityPolicy(StringBuilder contentSecurityPolicy, String value) {
        if (StringUtils.isNotBlank(value)) {
            if ("true".equalsIgnoreCase(value)) {
                contentSecurityPolicy.append("; ").append(SANDBOX);
            } else {
                contentSecurityPolicy.append("; ").append(SANDBOX).append(" ").append(value);
            }
        }
    }

    public void destroy() {
        //not needed
    }

}
