package unfiltered.oauth2

import unfiltered.request._
import unfiltered.response._

object OAuth2 {
  val QueryParam = "oauth_token"
  val BearerHeader = """Bearer ([\w|:|\/|.|%|-]+)""".r
    
  val TokenKey = "token"
  val Timestamp = "timestamp"
  val Nonce = "nonce"
  val BodyHash = "bodyhash"
  val Sig = "signature"
  
  /** Authorization: MAC header extractor */
  object MacHeader {
    val KeyVal = """(\w+)="([\w|:|\/|.|%|-]+)" """.trim.r
    val keys = Set.empty + TokenKey + Timestamp + Nonce + BodyHash + Sig

    def unapply(hvals: List[String]) = hvals match {
      case x :: xs if x startsWith "MAC " =>      
        Some(Map(hvals map { _.replace("MAC ", "") } flatMap {
          case KeyVal(k, v) if(keys.contains(k)) => Seq((k -> Seq(v)))
          case _ => Nil
        }: _*))
        
      case _ => None
    }
  }
  
  val XAuthorizedIdentity = "X-Authorized-Identity"
}

trait AuthenticationMethod

case class BearerAuth(token: String) extends AuthenticationMethod

case class MacAuth(token: String,
  timestamp: String,
  nonce: String,
  bodyhash: String,
  signature: String) extends AuthenticationMethod

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
  import javax.servlet.http.{HttpServletRequest}
  
  val source: AuthSource

  def intent = {
    case Params(params) & request =>
      val OAuth2BearerHeader = header
      val OAuth2MacHeader = macHeader
            
      request match {        
        case Authorization(headers) => headers match {
          case OAuth2MacHeader(p) => 
            try {
              authenticate(MacAuth(p(OAuth2.TokenKey)(0), p(OAuth2.Timestamp)(0),
                p(OAuth2.Nonce)(0), p(OAuth2.BodyHash)(0), p(OAuth2.Sig)(0)), request)
            }
            catch {
              case e: Exception => errorResponse(BadRequest, "invalid MAC header: " + headers.toString, request) 
            }
          
          case OAuth2BearerHeader(token) :: Nil => authenticate(BearerAuth(token), request) 
          
          case _ => errorResponse(Unauthorized, "", request)
        }
        
        case _ =>
          params.getOrElse(queryParameter, Nil).headOption match {
            case Some(token) => authenticate(BearerAuth(token), request)
            case _ => errorResponse(Unauthorized, "", request)
          }
      }
  }
  
  def authenticate[T <: HttpServletRequest](token: AuthenticationMethod, request: HttpRequest[T]) =
    source.authenticateToken(token, request) match {
      case Left(msg)   => errorResponse(Unauthorized, msg, request)
      case Right(user) =>
        request.underlying.setAttribute(OAuth2.XAuthorizedIdentity, user)
        Pass
    }
  
  def header = OAuth2.BearerHeader

  def macHeader = OAuth2.MacHeader
  
  def queryParameter: String = OAuth2.QueryParam
  
  def errorString(status: String, description: String) = """error="%s" error_description="%s" """.trim format(status, description)
  
  def errorResponse[T](status: Status, description: String,
      request: HttpRequest[T]): Responder[Any] = (status, description) match {
    case (Unauthorized, "") => Unauthorized ~> WWWAuthenticate("Bearer") ~> ResponseString("Bearer")
    case (Unauthorized, _)  =>
      Unauthorized ~> WWWAuthenticate("Bearer\n" + errorString("invalid_token", description)) ~>
      ResponseString(errorString("invalid_token", description))
      
    case (BadRequest, _)    => status ~> ResponseString(errorString("invalid_request", description))
    case (Forbidden, _)     => status ~> ResponseString(errorString("insufficient_scope", description))
    case _ => status ~> ResponseString(errorString(status.toString, description))
  }
}

/** Represents the `User` in an oauth interaction. */
trait UserLike {
  val id: String
}

/** Represents the authorization source that issued the access token. */
trait AuthSource {
  def authenticateToken[T](token: AuthenticationMethod, request: HttpRequest[T]): Either[String, UserLike]

  def realm: Option[String] = None
}
