package de.saville.csp;

import static de.saville.csp.ContentSecurityPolicyFilter.CONTENT_SECURITY_POLICY_HEADER;
import static de.saville.csp.ContentSecurityPolicyFilter.CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER;
import static de.saville.csp.ContentSecurityPolicyFilter.DEFAULT_SRC;
import static de.saville.csp.ContentSecurityPolicyFilter.IMG_SRC;
import static de.saville.csp.ContentSecurityPolicyFilter.KEYWORD_SELF;
import static de.saville.csp.ContentSecurityPolicyFilter.MEDIA_SRC;
import static de.saville.csp.ContentSecurityPolicyFilter.REPORT_URI;
import static de.saville.csp.ContentSecurityPolicyFilter.SANDBOX;
import static de.saville.csp.ContentSecurityPolicyFilter.SCRIPT_SRC;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;

@RunWith(JUnit4.class)
public class ContentSecurityPolicyFilterTest {
    private static final String DEFAULT_HEADER_VALUE = "default-src 'none'";
    private static final String REPORT_URL = "/testReportUrl";

    private ContentSecurityPolicyFilter contentSecurityPolicyFilter;
    private ServletRequest request;
    private HttpServletResponse response;
    private FilterChain filterChain;

    @Before
    public void setUp() {
        contentSecurityPolicyFilter = new ContentSecurityPolicyFilter();
        response = mock(HttpServletResponse.class);
        request = mock(ServletRequest.class);
        filterChain = mock(FilterChain.class);
    }

    @Test
    public void testDefaultValues() throws IOException, ServletException {
        // - GIVEN -
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, null));

        // - WHEN -
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);

        // - THEN -
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE);
    }

    @Test
    public void testDefaultSrcIsSelf() throws IOException, ServletException {
        // - GIVEN -
        contentSecurityPolicyFilter.init(mockFilterConfig(KEYWORD_SELF, null, null, null, null, null, null));

        // - WHEN -
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);

        // - THEN -
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, "default-src 'self'");
    }

    @Test
    public void testImageSrc() throws IOException, ServletException {
        // - GIVEN -
        contentSecurityPolicyFilter.init(mockFilterConfig(KEYWORD_SELF, "static.example.com", null, null, null, null, null));

        // - WHEN -
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);

        // - THEN -
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, "default-src 'self'; img-src static.example.com");
    }

    @Test
    public void testScriptSrc() throws IOException, ServletException {
        // - GIVEN -
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, "'self' js.example.com", null, null, null, null));

        // - WHEN -
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);

        // - THEN -
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, "default-src 'none'; script-src 'self' js.example.com");
    }

    @Test
    public void testMediaSrc() throws IOException, ServletException {
        // - GIVEN -
        contentSecurityPolicyFilter.init(mockFilterConfig(KEYWORD_SELF, null, null, "static.example.com", null, null, null));

        // - WHEN -
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);

        // - THEN -
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, "default-src 'self'; media-src static.example.com");
    }

    @Test
    public void testReportOnly() throws IOException, ServletException {
        // - GIVEN -
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, "true", REPORT_URL, null));

        // - WHEN -
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);

        // - THEN -
        assertHeader(CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER, DEFAULT_HEADER_VALUE + "; report-uri " + REPORT_URL);
    }

    @Test
    public void testReportUri() throws IOException, ServletException {
        // - GIVEN -
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, "false", REPORT_URL, null));

        // - WHEN -
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);

        // - THEN -
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; report-uri " + REPORT_URL);
    }

    @Test
    public void testSandbox() throws IOException, ServletException {
        // - GIVEN -
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, "true"));

        // - WHEN -
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);

        // - THEN -
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; " + SANDBOX);
    }

    @Test
    public void testSandboxAllowScripts() throws IOException, ServletException {
        // - GIVEN -
        contentSecurityPolicyFilter.init(mockFilterConfig(null, null, null, null, null, null, "allow-scripts"));

        // - WHEN -
        contentSecurityPolicyFilter.doFilter(request, response, filterChain);

        // - THEN -
        assertHeader(CONTENT_SECURITY_POLICY_HEADER, DEFAULT_HEADER_VALUE + "; " + SANDBOX + " allow-scripts");
    }

    /*
     * -------------------------- HELPER methods -------------------------------
     */

    private FilterConfig mockFilterConfig(String defaultSrc, String imgSrc, String scriptSrc, String mediaSrc, String reportOnly, String reportUri,
            String sandbox) {
        FilterConfig filterConfig = mock(FilterConfig.class);
        when(filterConfig.getInitParameter(DEFAULT_SRC)).thenReturn(defaultSrc);
        when(filterConfig.getInitParameter(IMG_SRC)).thenReturn(imgSrc);
        when(filterConfig.getInitParameter(SCRIPT_SRC)).thenReturn(scriptSrc);
        when(filterConfig.getInitParameter(MEDIA_SRC)).thenReturn(mediaSrc);
        when(filterConfig.getInitParameter("report-only")).thenReturn(reportOnly);
        when(filterConfig.getInitParameter(REPORT_URI)).thenReturn(reportUri);
        when(filterConfig.getInitParameter(SANDBOX)).thenReturn(sandbox);

        return filterConfig;
    }

    private Header getHeader() {
        ArgumentCaptor<String> headerName = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> headerValue = ArgumentCaptor.forClass(String.class);
        verify(response).addHeader(headerName.capture(), headerValue.capture());
        return new Header(headerName.getValue(), headerValue.getValue());
    }

    private void assertHeader(String expectedHeaderName, String expectedHeaderValue) {
        Header header = getHeader();
        assertThat(header.name, is(expectedHeaderName));
        assertThat(header.value, is(expectedHeaderValue));
    }

    private static final class Header {
        public String name;
        public String value;

        public Header(String name, String value) {
            this.name = name;
            this.value = value;
        }
    }

}
