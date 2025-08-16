package org.springframework.web.filter;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.util.ContentCachingResponseWrapper;
import org.springframework.web.util.WebUtils;

import java.io.IOException;

/**
 * Extension of ShallowEtagHeaderFilter that uses SHA-512 instead of default hashing
 */
public class Sha512ShallowEtagHeaderFilter extends ShallowEtagHeaderFilter {

    /**
     * The default implementation uses a simple MD5 hash, but we're overriding the entire
     * doFilter method to use SHA-512 instead
     */
	@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                   FilterChain filterChain) throws ServletException, IOException {
        // Call the parent implementation first
        super.doFilterInternal(request, response, filterChain);
        
        // If the response is wrapped, we can access its content and replace the ETag
        ContentCachingResponseWrapper wrapper = WebUtils.getNativeResponse(response, ContentCachingResponseWrapper.class);
        if (wrapper != null) {
            byte[] responseBytes = wrapper.getContentAsByteArray();
            if (responseBytes.length > 0) {
                // Generate SHA-512 hash
                HashCode hash = Hashing.sha512().hashBytes(responseBytes);
                String etag = "\"" + hash + "\"";
                
                // Replace the ETag header
                response.setHeader("ETag", etag);
            }
        }
	}
}
