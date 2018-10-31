require "sinatra"
require "sinatra/flash"
require "haml"
require "net/ldap"
require 'securerandom'
require 'digest/sha1'
require 'base64'

# Generate 16 hex characters of random
def generate_salt
  SecureRandom.hex(16)
end

# Hash the password using the given salt. If no salt is supplied, use a new
# one.
def encode_password(plaintext, salt=generate_salt)
  raise ArgumentError.new("Password must not be nil") if plaintext.nil?

  ssha = Digest::SHA1.digest(plaintext+salt) + salt

  return "{SSHA}" + Base64.strict_encode64(ssha).chomp
end

# Check the supplied password against the given hash and return true if they
# match, else false.
def check_password(password, ssha)
  decoded = Base64.decode64(ssha.gsub(/^{SSHA}/, ''))
  hash = decoded[0..19] # isolate the hash
  salt = decoded[20..-1] # isolate the salt

  return encode_password(password, salt) == ssha
end

set :environment, :production

SESSIONSECRET = File.read("session.secret").chomp

use Rack::Session::Cookie,
    :key => 'rack.session',
    :path => '/',
    :secret => SESSIONSECRET

helpers do
  def h(text)
    Rack::Utils.escape_html(text)
  end
end

LDAPPASSWD = File.read("ldap.passwd").chomp

ldapconn = Net::LDAP.new(
  :host => '127.0.0.1',
  :port => 389,
  :auth => {
    :method => :simple,
    :username => "cn=admin,dc=york,dc=hackspace,dc=org,dc=uk",
    :password => LDAPPASSWD
  }
)

userbase = "ou=Users,dc=york,dc=hackspace,dc=org,dc=uk"
groupbase = "ou=Groups,dc=york,dc=hackspace,dc=org,dc=uk"














def err(text)
  if flash[:error].nil? then
    flash[:error] = [text]
  else
    flash[:error] << text
  end
end

def succ(text)
  if flash[:success].nil? then
    flash[:success] = [text]
  else
    flash[:success] << text
  end
end

before do
  pass if request.path_info.split("/")[1] == "login"
  unless session["ldap"]
    err "Please log in."
    redirect "/login"
  end
end

get "/" do
  haml :index
end

get "/login" do
  if session["ldap"]
    redirect "/"
  else
    haml :login
  end
end

post "/login" do
  unless session["ldap"]
    filter = Net::LDAP::Filter.eq("uid", params["username"])
    ldap = ldapconn.search(:base => userbase, :filter => filter)[0]

    if ldap.nil?
      err "User does not exist."
      redirect "/login"
    end

    hash = ldap.userPassword[0]

    filter = Net::LDAP::Filter.eq("cn", "Trustees")
    admins = ldapconn.search(:base => groupbase, :filter => filter)[0].member

    if check_password(params["password"], hash)
      session["ldap"] = ldap
      if admins.include?("uid=#{params["username"]},#{userbase}")
        session["trustee"] = true
      end
    end
  end

  succ "Logged in"
  redirect "/"
end

get "/logout" do
  session.delete("ldap")
  session.delete("trustee")
  succ "Logged out."
  redirect "/login"
end

get "/adduser" do
  if session["trustee"]
    haml :adduser
  else
    err "Only trustees can add users."
    redirect "/"
  end
end

post "/adduser" do
  if session["trustee"]
    uid = params["username"]

    filter = Net::LDAP::Filter.eq("uid", uid)
    ldap = ldapconn.search(:base => userbase, :filter => filter)[0]
    unless ldap.nil?
      err "Username exists."
      redirect "/adduser" +
        "?username=#{uid}" +
        "&firstname=#{params["firstname"]}" +
        "&surname=#{params["surname"]}" +
        "&member=#{params["member"].nil? ? false : true}" +
        "&trustee=#{params["trustee"].nil? ? false : true}" +
        "&radius=#{params["radius"].nil? ? false : true}" +
        "&unix=#{params["unix"].nil? ? false : true}"
    end

    hash = encode_password(params["password"])
    ldapconn.add(
      :dn => "uid=#{uid},#{userbase}",
      :attributes => {
        :cn => params["firstname"],
        :sn => params["surname"],
        :uid => uid,
        :userPassword => hash,
        :objectclass => [
          "top",
          "inetOrgPerson",
          "person",
          "organizationalPerson"
        ]
      }
    )

    unless params["member"].nil? then
      ldapconn.add_attribute(
        "cn=Members,#{groupbase}",
        :member,
        "uid=#{uid},#{userbase}"
      )
    end

    unless params["trustee"].nil? then
      ldapconn.add_attribute(
        "cn=Trustees,#{groupbase}",
        :member,
        "uid=#{uid},#{userbase}"
      )
    end

    unless params["radius"].nil? then
      ldapconn.add_attribute(
        "cn=Radius,#{groupbase}",
        :member,
        "uid=#{uid},#{userbase}"
      )
    end

    unless params["unix"].nil? then
      ldapconn.add_attribute(
        "cn=Unix,#{groupbase}",
        :member,
        "uid=#{uid},#{userbase}"
      )
    end

    succ "User added."
  else
    err "Only trustees can add users."
  end

  redirect "/"
end

get "/deluser" do
  if session["trustee"]
    haml :deluser
  else
    err "Only trustees can delete users."
    redirect "/"
  end
end

post "/deluser" do
  if session["trustee"]
    uid = params["username"]
    uid2 = params["username2"]

    if uid != uid2
      err "Usernames did not match."
      redirect "/deluser?username=#{uid}"
    end

    rdn = "uid=#{uid},#{userbase}"

    ldapconn.delete(
      :dn => rdn
    )

    ldapconn.modify(
      :dn => "cn=Members,#{groupbase}",
      :operations => [
        [:delete, :member, rdn]
      ]
    )

    ldapconn.modify(
      :dn => "cn=Trustees,#{groupbase}",
      :operations => [
        [:delete, :member, rdn]
      ]
    )

    ldapconn.modify(
      :dn => "cn=Radius,#{groupbase}",
      :operations => [
        [:delete, :member, rdn]
      ]
    )

    ldapconn.modify(
      :dn => "cn=Unix,#{groupbase}",
      :operations => [
        [:delete, :member, rdn]
      ]
    )

    succ "User deleted."
  else
    err "Only trustees can delete users."
  end

  redirect "/"
end

get "/passwd" do
  haml :passwd
end

post "/passwd" do
  uid = session["ldap"].uid[0]
  if session["trustee"] && params["username"]
    uid = params["username"]
  end

  newhash = encode_password(params["password"])

  ldapconn.replace_attribute(
    "uid=#{uid},#{userbase}",
    :userPassword,
    newhash
  )

  succ "Password changed."
  redirect "/"
end

get "/lsuser" do
  unless session["trustee"]
    err "Only trustees can list users."
    redirect "/"
  end

  filter = Net::LDAP::Filter.eq("objectClass", "organizationalUnit").~
  @ldapusers = ldapconn.search(:base => userbase, :filter => filter)
  @ldapgroups = {
    members: ldapconn.search(:base => groupbase,
                             :filter => Net::LDAP::Filter.eq("cn", "Members"))[0].member,
    trustees: ldapconn.search(:base => groupbase,
                              :filter => Net::LDAP::Filter.eq("cn", "Trustees"))[0].member,
    radius: ldapconn.search(:base => groupbase,
                            :filter => Net::LDAP::Filter.eq("cn", "Radius"))[0].member,
    unix: ldapconn.search(:base => groupbase,
                          :filter => Net::LDAP::Filter.eq("cn", "Unix"))[0].member
  }
  haml :lsuser
end

get "/moduser" do
  uid = session["ldap"].uid[0]
  if session["trustee"] && params["username"]
    uid = params["username"]
  end

  filter = Net::LDAP::Filter.eq("uid", uid)
  ldap = ldapconn.search(:base => userbase, :filter => filter)[0]

  members = ldapconn.search(:base => groupbase,
                            :filter => Net::LDAP::Filter.eq("cn", "Members"))[0].member
  trustees = ldapconn.search(:base => groupbase,
                             :filter => Net::LDAP::Filter.eq("cn", "Trustees"))[0].member
  radius = ldapconn.search(:base => groupbase,
                           :filter => Net::LDAP::Filter.eq("cn", "Radius"))[0].member
  unix = ldapconn.search(:base => groupbase,
                         :filter => Net::LDAP::Filter.eq("cn", "Unix"))[0].member

  rdn = "uid=#{ldap.uid[0]},#{userbase}"

  @luser = {
    uid: ldap.uid[0],
    cn: ldap.cn[0],
    sn: ldap.sn[0],
    member: members.include?(rdn),
    trustee: trustees.include?(rdn),
    radius: radius.include?(rdn),
    unix: unix.include?(rdn)
  }

  haml :moduser
end

post "/moduser" do
  uid = session["ldap"].uid[0]
  if session["trustee"] && params["username"]
    uid = params["username"]
  end

  rdn = "uid=#{uid},#{userbase}"

  ldapconn.modify(
    :dn => rdn,
    :operations => [
      [:replace, :cn, params["firstname"]],
      [:replace, :sn, params["surname"]]
    ]
  )

  if session["trustee"]
    ldapconn.modify(
      :dn => "cn=Members,#{groupbase}",
      :operations => [
        [:delete, :member, rdn]
      ]
    )
    unless params["member"].nil? then
      ldapconn.add_attribute(
        "cn=Members,#{groupbase}",
        :member,
        "uid=#{uid},#{userbase}"
      )
    end

    ldapconn.modify(
      :dn => "cn=Trustees,#{groupbase}",
      :operations => [
        [:delete, :member, rdn]
      ]
    )
    unless params["trustee"].nil? then
      ldapconn.add_attribute(
        "cn=Trustees,#{groupbase}",
        :member,
        "uid=#{uid},#{userbase}"
      )
    end

    ldapconn.modify(
      :dn => "cn=Radius,#{groupbase}",
      :operations => [
        [:delete, :member, rdn]
      ]
    )
    unless params["radius"].nil? then
      ldapconn.add_attribute(
        "cn=Radius,#{groupbase}",
        :member,
        "uid=#{uid},#{userbase}"
      )
    end

    ldapconn.modify(
      :dn => "cn=Unix,#{groupbase}",
      :operations => [
        [:delete, :member, rdn]
      ]
    )
    unless params["unix"].nil? then
      ldapconn.add_attribute(
        "cn=Unix,#{groupbase}",
        :member,
        "uid=#{uid},#{userbase}"
      )
    end
  end

  succ "User modified."

  redirect "/"
end
