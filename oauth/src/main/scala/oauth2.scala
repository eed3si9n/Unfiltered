package unfiltered.oauth2

import unfiltered.request._
import unfiltered.response._

object OAuth2 {
  val TokenKey = "oauth_token"
  val XAuthorizedIdentity = "X-Authorized-Identity"
  val Header = """OAuth ([\w|:|\/|.|%|-]+)""".r
}

/** After your application has obtained an access token, your app can use it to access APIs by
 * including it in either an oauth_token query parameter or an Authorization: OAuth header.
 *
 * To call API using HTTP header.
 *
 *     GET /api/1//feeds.js HTTP/1.1
 *     Authorization: OAuth YOUR_ACCESS_TOKEN
 *     Host: www.example.com
 */
case class Protection(source: AuthSource) extends ProtectionLike

/** Provides OAuth2 protection implementation. Extend this trait to customize query string `oauth_token`, etc. */
trait ProtectionLike extends unfiltered.filter.Plan {
  val source: AuthSource

  def intent = {
    case Params(params) & request =>
      val OAuthTokenHeader = header
      def queryBased = params.getOrElse(queryParameter, Nil).headOption
      def accessToken = request match {
        case Authorization(headers) => headers match {
          case OAuthTokenHeader(token) :: xs => Some(token)
          case _ => queryBased
        }
        case _ => queryBased
      }

      accessToken map { source.authenticateToken(_, request) match {
        case Left(msg)   => unauthorizedResponse(msg, request)
        case Right(user) =>
          request.underlying.setAttribute(OAuth2.XAuthorizedIdentity, user)
          Pass
      }} getOrElse {unauthorizedResponse("Unauthorized", request)}
  }

  def header = OAuth2.Header

  def queryParameter: String = OAuth2.TokenKey

  def unauthorizedResponse[T](msg: String, request: HttpRequest[T]): Responder[Any] = {
    import javax.servlet.http.{HttpServletRequest}

    Unauthorized ~>
    (request.underlying match {
      case underlying: HttpServletRequest =>
        WWWAuthenticate("OAuth realm=\"%s\"" format(source.realm getOrElse {underlying.getRequestURL.toString}))
      case _ =>
        WWWAuthenticate("OAuth realm=\"%s\"" format(source.realm getOrElse {""}))
    }) ~>
    ResponseString("401 Unauthorized")
  }
}

/** Represents the `User` in an oauth interaction. */
trait UserLike {
  val id: String
}

/** Represents the authorization source that issued the access token. */
trait AuthSource {
  def authenticateToken[T](access_token: String, request: HttpRequest[T]): Either[String, UserLike]

  def realm: Option[String] = None
}
