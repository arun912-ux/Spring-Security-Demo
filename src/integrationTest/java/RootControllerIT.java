import com.example.springsecuritydemo.SpringSecurityDemoApplication;
import com.example.springsecuritydemo.config.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ActiveProfiles("integration")
@ContextConfiguration(classes = {
        SpringSecurityDemoApplication.class,
        SecurityConfig.class
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class RootControllerIT {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testLogClaims200() throws Exception {

        mockMvc.perform(get("/api/logclaims")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                )
                .andExpect(status().isOk());

    }

    @Test
    @WithMockUser(authorities = {"READ_WRITE"})
    public void testLogClaimsWithRoles() throws Exception {

        mockMvc.perform(get("/api/logclaims")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                )
                .andExpect(status().isOk());

    }

    @Test
    @WithMockUser(authorities = {"READ_WRITE"})
    public void testLogAdmin200() throws Exception {

        mockMvc.perform(get("/api/admin")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                )
                .andExpect(status().isOk())
                .andExpect(content().string("Hello Admin"));
    }

    @Test
    @WithMockUser(authorities = {"READ_ONLY"})
    public void testLogAdmin403() throws Exception {

        mockMvc.perform(get("/api/admin")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                )
                .andExpect(status().isForbidden());
    }

}
