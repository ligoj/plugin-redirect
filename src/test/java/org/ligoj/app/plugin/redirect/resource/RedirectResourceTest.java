package org.ligoj.app.plugin.redirect.resource;

import java.io.IOException;
import java.net.URISyntaxException;

import javax.transaction.Transactional;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.ligoj.app.AbstractAppTest;
import org.ligoj.app.plugin.id.resource.CompanyResource;
import org.ligoj.bootstrap.dao.system.SystemUserSettingRepository;
import org.ligoj.bootstrap.model.system.SystemConfiguration;
import org.ligoj.bootstrap.model.system.SystemUserSetting;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Test class of {@link RedirectResource}
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(locations = "classpath:/META-INF/spring/application-context-test.xml")
@Rollback
@Transactional
public class RedirectResourceTest extends AbstractAppTest {

	@Autowired
	private RedirectResource resource;

	@Autowired
	private SystemUserSettingRepository userSettingRepository;

	@BeforeEach
	public void prepareConfiguration() throws IOException {
		persistEntities("csv", SystemConfiguration.class);
	}

	@Test
	public void handleRedirectAnonymousNoCookie() throws URISyntaxException {
		SecurityContextHolder.clearContext();

		final Response response = resource.handleRedirect(null);
		Assertions.assertNull(response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH));
		Assertions.assertEquals("http://localhost:8081/external", response.getHeaderString("location"));
	}

	@Test
	public void handleRedirectAnonymousCookieNoSetting() throws URISyntaxException {
		SecurityContextHolder.clearContext();

		final Response response = resource.handleRedirect(DEFAULT_USER + "|hash");
		Assertions.assertNull(response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH));
		Assertions.assertEquals("http://localhost:8081/external", response.getHeaderString("location"));
	}

	@Test
	public void handleRedirectAnonymousCookieNotMatch() throws URISyntaxException {
		SecurityContextHolder.clearContext();

		final SystemUserSetting setting = new SystemUserSetting();
		setting.setLogin(DEFAULT_USER);
		setting.setName(RedirectResource.PREFERRED_HASH);
		setting.setValue("-");
		userSettingRepository.save(setting);
		em.flush();
		em.clear();

		final Response response = resource.handleRedirect(DEFAULT_USER + "|hash");
		Assertions.assertNull(response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH));
		Assertions.assertEquals("http://localhost:8081/external", response.getHeaderString("location"));
	}

	@Test
	public void handleRedirectAnonymous() throws URISyntaxException {
		SecurityContextHolder.clearContext();

		final SystemUserSetting setting = new SystemUserSetting();
		setting.setLogin(DEFAULT_USER);
		setting.setName(RedirectResource.PREFERRED_HASH);
		setting.setValue("hash");
		userSettingRepository.save(setting);
		final SystemUserSetting setting2 = new SystemUserSetting();
		setting2.setLogin(DEFAULT_USER);
		setting2.setName(RedirectResource.PREFERRED_URL);
		setting2.setValue("http://localhost:1/any");
		userSettingRepository.save(setting2);
		em.flush();
		em.clear();

		final Response response = resource.handleRedirect(DEFAULT_USER + "|hash");
		Assertions.assertNull(response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH));
		Assertions.assertEquals("http://localhost:1/any", response.getHeaderString("location"));
	}

	@Test
	public void handleRedirect() throws URISyntaxException {
		final SystemUserSetting setting = new SystemUserSetting();
		setting.setLogin(DEFAULT_USER);
		setting.setName(RedirectResource.PREFERRED_HASH);
		setting.setValue("hash");
		userSettingRepository.save(setting);
		final SystemUserSetting setting2 = new SystemUserSetting();
		setting2.setLogin(DEFAULT_USER);
		setting2.setName(RedirectResource.PREFERRED_URL);
		setting2.setValue("http://localhost:1/any");
		userSettingRepository.save(setting2);
		em.flush();
		em.clear();

		final Response response = resource.handleRedirect("any");
		Assertions.assertEquals(DEFAULT_USER + "|hash",
				response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH).getValue());
		Assertions.assertEquals("http://localhost:1/any", response.getHeaderString("location"));
	}

	@Test
	public void handleRedirectNoCookie() throws URISyntaxException {
		final SystemUserSetting setting = new SystemUserSetting();
		setting.setLogin(DEFAULT_USER);
		setting.setName(RedirectResource.PREFERRED_HASH);
		setting.setValue("hash");
		userSettingRepository.save(setting);
		final SystemUserSetting setting2 = new SystemUserSetting();
		setting2.setLogin(DEFAULT_USER);
		setting2.setName(RedirectResource.PREFERRED_URL);
		setting2.setValue("http://localhost:1/any");
		userSettingRepository.save(setting2);
		em.flush();
		em.clear();

		final Response response = resource.handleRedirect(null);
		Assertions.assertEquals(DEFAULT_USER + "|hash",
				response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH).getValue());
		Assertions.assertEquals("http://localhost:1/any", response.getHeaderString("location"));
	}

	@Test
	public void buildCookieResponseNoHash() {
		final ResponseBuilder rb = Response.noContent();
		resource.accept(rb, new UsernamePasswordAuthenticationToken("any", "n/a"));
		final Response response = rb.build();
		Assertions.assertNull(response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH));
		Assertions.assertNull(response.getHeaderString("location"));
	}

	@Test
	public void buildCookieResponse() {
		final SystemUserSetting setting = new SystemUserSetting();
		setting.setLogin(DEFAULT_USER);
		setting.setName(RedirectResource.PREFERRED_HASH);
		setting.setValue("hash");
		userSettingRepository.save(setting);

		final ResponseBuilder rb = Response.noContent();
		resource.accept(rb, new UsernamePasswordAuthenticationToken(DEFAULT_USER, "n/a"));
		final Response response = rb.build();

		Assertions.assertEquals("junit|hash", response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH).getValue());
		Assertions.assertNull(response.getHeaderString("location"));
	}

	@Test
	public void redirectToHomeAnonymous() throws URISyntaxException {
		SecurityContextHolder.clearContext();
		final Response response = resource.redirectToHome().build();
		Assertions.assertEquals(302, response.getStatus());
		Assertions.assertEquals("http://localhost:8081/external", response.getHeaderString("location"));
	}

	/**
	 * Special Spring-security anonymous user.
	 */
	@Test
	public void redirectToHomeAnonymous2() throws URISyntaxException {
		initSpringSecurityContext("anonymousUser");
		final Response response = resource.redirectToHome().build();
		Assertions.assertEquals(302, response.getStatus());
		Assertions.assertEquals("http://localhost:8081/external", response.getHeaderString("location"));
	}

	@Test
	public void redirectToHomeInternal() throws URISyntaxException {
		initSpringSecurityContext("fdaugan");
		final Response response = resource.redirectToHome().build();
		Assertions.assertEquals(302, response.getStatus());
		Assertions.assertEquals("http://localhost:8081/internal", response.getHeaderString("location"));
	}

	@Test
	public void redirectToHomeExternal() throws URISyntaxException {
		initSpringSecurityContext("fdoe2");
		final RedirectResource resource = new RedirectResource();
		applicationContext.getAutowireCapableBeanFactory().autowireBean(resource);
		resource.companyResource = Mockito.mock(CompanyResource.class);
		
		final Response response = resource.redirectToHome().build();
		Assertions.assertEquals(302, response.getStatus());
		Assertions.assertEquals("http://localhost:8081/external", response.getHeaderString("location"));
	}

	@Test
	public void saveOrUpdate() throws URISyntaxException {
		Response response = resource.saveOrUpdate("http://localhost:1/any");
		final String cookieValue = response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH).getValue();
		Assertions.assertTrue(cookieValue.startsWith(DEFAULT_USER + "|"));
		Assertions.assertNull(response.getHeaderString("location"));

		response = resource.handleRedirect(null);
		Assertions.assertEquals(cookieValue, response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH).getValue());
		Assertions.assertEquals("http://localhost:1/any", response.getHeaderString("location"));

		// Logout
		SecurityContextHolder.clearContext();
		response = resource.handleRedirect(cookieValue);
		Assertions.assertNull(response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH));
		Assertions.assertEquals("http://localhost:1/any", response.getHeaderString("location"));

		// Change URL
		userSettingRepository.findByLoginAndName(DEFAULT_USER, RedirectResource.PREFERRED_URL)
				.setValue("http://localhost:2/any");
		em.flush();
		em.clear();

		response = resource.handleRedirect(cookieValue);
		Assertions.assertNull(response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH));
		Assertions.assertEquals("http://localhost:2/any", response.getHeaderString("location"));

		// Change hash
		userSettingRepository.findByLoginAndName(DEFAULT_USER, RedirectResource.PREFERRED_HASH).setValue("new-hash");
		userSettingRepository.findByLoginAndName(DEFAULT_USER, RedirectResource.PREFERRED_URL)
				.setValue("http://localhost:2/any");
		em.flush();
		em.clear();
		response = resource.handleRedirect(cookieValue);
		Assertions.assertNull(response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH));
		Assertions.assertEquals("http://localhost:8081/external", response.getHeaderString("location"));

		// Login
		initSpringSecurityContext(DEFAULT_USER);
		response = resource.handleRedirect(null);
		Assertions.assertEquals(DEFAULT_USER + "|new-hash",
				response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH).getValue());
		Assertions.assertEquals("http://localhost:2/any", response.getHeaderString("location"));
	}

	@Test
	public void saveOrUpdateUpdate() throws URISyntaxException {
		final SystemUserSetting setting = new SystemUserSetting();
		setting.setLogin(DEFAULT_USER);
		setting.setName(RedirectResource.PREFERRED_HASH);
		setting.setValue("hash");
		userSettingRepository.save(setting);
		final SystemUserSetting setting2 = new SystemUserSetting();
		setting2.setLogin(DEFAULT_USER);
		setting2.setName(RedirectResource.PREFERRED_URL);
		setting2.setValue("http://localhost:1/any");
		userSettingRepository.save(setting2);
		em.flush();
		em.clear();

		Response response = resource.saveOrUpdate("http://localhost:2/any");
		em.flush();
		em.clear();
		final String cookieValue = response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH).getValue();
		Assertions.assertEquals(DEFAULT_USER + "|hash", cookieValue);
		Assertions.assertNull(response.getHeaderString("location"));

		response = resource.handleRedirect(null);
		em.flush();
		em.clear();
		Assertions.assertEquals(DEFAULT_USER + "|hash",
				response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH).getValue());
		Assertions.assertEquals("http://localhost:2/any", response.getHeaderString("location"));
	}

	public void saveOrUpdateNotCreated() {
		final Response response = resource.saveOrUpdate("http://localhost:2/any");
		Assertions.assertNull(response.getCookies().get(RedirectResource.PREFERRED_COOKIE_HASH));
		Assertions.assertNull(response.getHeaderString("location"));
	}
	
	@Test
	public void getKey() {
		Assertions.assertEquals("feature:redirect", resource.getKey());
	}

}
