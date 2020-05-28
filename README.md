# Howto springboot security

This is an example of Oauth2 integration on spring boot application (spring boot>=2.1)

## The repository

There is multiple branch. It is linked to the use-case you have: 

Data needed to provide security role

- Simple Authentication: Only uid is needed to get the security role. UserInfo is not called (no need).
- Complex authentication: a call to UserInfo (cached!!!!!!!) is needed to resolve security role.

Development type:

- Web MVC
- Webflux (reactive programming)
 
## Branches
 
|             | Simple Authentication | Complex Authentication |
| ----------- | --------------------- | ---------------------- |
| **Web MVC** | [simple](https://github.com/dktunited/howto-springboot-security/tree/simple) | [complex](https://github.com/dktunited/howto-springboot-security/tree/complex) |
| **Webflux** | [simple-reactive](https://github.com/dktunited/howto-springboot-security/tree/simple-reactive) | [complex-reactive](https://github.com/dktunited/howto-springboot-security/tree/complex-reactive) |

