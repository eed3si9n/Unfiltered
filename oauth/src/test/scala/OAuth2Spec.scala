package unfiltered.oauth2

import org.specs._

object OAuth2Spec extends Specification with unfiltered.spec.jetty.Served {

  import unfiltered.response._
  import unfiltered.request._
  import unfiltered.request.{Path => UFPath}
  import dispatch._
  
  class User(val id: String) extends UserLike
  object User {
    import javax.servlet.http.{HttpServletRequest}
    
    def unapply[T <: HttpServletRequest](request: HttpRequest[T]): Option[User] =
      request.underlying.getAttribute(unfiltered.oauth2.OAuth2.XAuthorizedIdentity) match {
        case user: User => Some(user)
        case _ => None
      }
  }
  
  def setup = { server =>
    val source = new AuthSource {
      def authenticateToken[T](access_token: String, request: HttpRequest[T]): Either[String, UserLike] = access_token match {
        case "good_token" => Right(new User("test_user"))
        case _ => Left("bad token")
      }

      override def realm: Option[String] = Some("Mock Source")
    }
    
    server.filter(Protection(source))
    .filter(unfiltered.filter.Planify {
      case User(user) => ResponseString(user.id)
    })
  }

  "oauth 2" should {
    "authenticate valid access token" in {
      val http = new Http
      val oauth_token = Map("oauth_token" -> "good_token")
      val user = http(host / "user" <<? oauth_token as_str)
      user must_=="test_user"
    }
  }
}
