/*    Copyright 2009 10gen Inc.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "mongo/platform/basic.h"

#include "mongo/util/net/hostandport.h"

#include <boost/functional/hash.hpp>

#include "mongo/base/parse_number.h"
#include "mongo/base/status.h"
#include "mongo/base/status_with.h"
#include "mongo/base/string_data.h"
#include "mongo/bson/util/builder.h"
#include "mongo/client/options.h"
#include "mongo/db/jsobj.h"
#include "mongo/util/mongoutils/str.h"
#include "mongo/util/net/sock.h"
#include "mongo/util/assert_util.h"

#ifdef ROBOMONGO
#define DEFAULT_SSH_PORT 22
#define DEFAULT_SSH_HOST ""
#include "mongo/db/json.h"

namespace Robomongo
{
#ifdef MONGO_SSL
    struct SSLInfo
    {
        SSLInfo():_sslSupport(false),_sslPEMKeyFile(){}
        SSLInfo(bool ssl,const std::string &key):_sslSupport(ssl),_sslPEMKeyFile(key){}
        explicit SSLInfo(const mongo::BSONElement &elem):_sslSupport(false),_sslPEMKeyFile()
        {
            if(!elem.eoo()){
                mongo::BSONObj obj = elem.Obj();
                _sslSupport = obj.getField("sslSupport").Bool();
                _sslPEMKeyFile = obj.getField("sslPEMKeyFile").String();
            }
        }

        mongo::BSONObj toBSONObj() const
        {
            mongo::BSONObjBuilder b;
            b.append("SSL",BSON("sslSupport" << _sslSupport  << "sslPEMKeyFile" << _sslPEMKeyFile));
            return b.obj();
        }
        bool isValid() const {return _sslSupport;}
        bool _sslSupport;
        std::string _sslPEMKeyFile;
    };

    inline std::ostream& operator<< (std::ostream& stream, const SSLInfo& info)
    {
        stream << info.toBSONObj().toString();
        return stream;
    }

    inline bool operator==(const SSLInfo& r,const SSLInfo& l)
    {
        return r._sslSupport == l._sslSupport && r._sslPEMKeyFile == l._sslPEMKeyFile;
    }
#endif
#ifdef SSH_SUPPORT_ENABLED
    struct PublicKey
    {
        PublicKey():_publicKey(),_privateKey(),_passphrase(){}
        PublicKey(const std::string &publicKey, const std::string &privateKey, const std::string &passphrase = ""):_publicKey(publicKey),_privateKey(privateKey),_passphrase(passphrase){}
        explicit PublicKey(const mongo::BSONObj &obj):_publicKey(),_privateKey()//abc+dsc+passphrase
        {
            _publicKey = obj.getField("publicKey").String();
            _privateKey = obj.getField("privateKey").String();
            _passphrase = obj.getField("passphrase").String();
        }

        mongo::BSONObj toBSONObj() const
        {
            return BSON( "publicKey" << _publicKey << "privateKey" << _privateKey << "passphrase" << _passphrase);
        }
        bool isValid() const {return !_privateKey.empty(); }
        std::string _publicKey;
        std::string _privateKey;
        std::string _passphrase;
    };

    inline bool operator==(const PublicKey& r,const PublicKey& l)
    {
        return r._publicKey == l._publicKey && r._privateKey == l._privateKey && r._passphrase == l._passphrase;
    }

    inline std::ostream& operator<< (std::ostream& stream, const PublicKey& key)
    {
        stream << key.toBSONObj().toString();
        return stream;
    }

    struct SSHInfo
    {
        enum SupportedAuthenticationMetods
        {
            UNKNOWN = 0,
            PASSWORD = 1,
            PUBLICKEY = 2
        };

        SSHInfo():_hostName(DEFAULT_SSH_HOST),_userName(),_port(DEFAULT_SSH_PORT),_password(),_publicKey(),_currentMethod(UNKNOWN)
        {

        }

        SSHInfo(const std::string &hostName, int port, const std::string &userName,  const std::string &password, const PublicKey &publicKey, SupportedAuthenticationMetods method)
            :_hostName(hostName),_port(port),_userName(userName),_password(password),_publicKey(publicKey),_currentMethod(method)
        {

        }

        explicit SSHInfo(const mongo::BSONElement &elem):_hostName(DEFAULT_SSH_HOST),_userName(),_port(DEFAULT_SSH_PORT),_password(),_publicKey(),_currentMethod(UNKNOWN)
        {
            if(!elem.eoo()){
                mongo::BSONObj obj = elem.Obj();
                _hostName = obj.getField("host").String();
                _port = obj.getField("port").Int();
                _userName = obj.getField("user").String();
                _password = obj.getField("password").String();
                _publicKey = PublicKey(obj.getField("publicKey").Obj());
                _currentMethod = static_cast<SupportedAuthenticationMetods>(obj.getField("currentMethod").Int());
            }
        }

        mongo::BSONObj toBSONObj() const
        {
            mongo::BSONObjBuilder b;
            b.append("SSH",BSON("host" << _hostName << "port" << _port << "user" << _userName << "password" << _password << "publicKey" << _publicKey.toBSONObj() << "currentMethod" << _currentMethod ));
            return b.obj();
        }
        bool isValid() const { return _currentMethod != UNKNOWN; }
        SupportedAuthenticationMetods authMethod() const { return _currentMethod; }

        std::string _hostName;
        int _port;
        std::string _userName;
        std::string _password;
        PublicKey _publicKey;
        SupportedAuthenticationMetods _currentMethod;
    };

    inline std::ostream& operator<< (std::ostream& stream, const SSHInfo& info)
    {
        stream << info.toBSONObj().toString();
        return stream;
    }

    inline bool operator==(const SSHInfo& r,const SSHInfo& l)
    {
        return r._hostName == l._hostName && r._password == l._password && r._port == l._port && r._publicKey==l._publicKey && r._userName == l._userName && r._publicKey == l._publicKey;
    }
#endif
}
#endif

namespace mongo {

StatusWith<HostAndPort> HostAndPort::parse(const StringData& text) {
    HostAndPort result;
    Status status = result.initialize(text);
    if (!status.isOK()) {
        return StatusWith<HostAndPort>(status);
    }
    return StatusWith<HostAndPort>(result);
}

HostAndPort::HostAndPort() : _port(-1) {}

HostAndPort::HostAndPort(const StringData& text) {
    uassertStatusOK(initialize(text));
}

HostAndPort::HostAndPort(const std::string& h, int p) : _host(h), _port(p) {}

bool HostAndPort::operator<(const HostAndPort& r) const {
    const int cmp = host().compare(r.host());
    if (cmp)
        return cmp < 0;
    return port() < r.port();
}

#ifdef ROBOMONGO
bool HostAndPort::operator==(const HostAndPort& r) const {
    return host() == r.host() && port() == r.port() && sshInfo() == r.sshInfo() && sslInfo() == r.sslInfo();
}
#else
bool HostAndPort::operator==(const HostAndPort& r) const {
    return host() == r.host() && port() == r.port();
}
#endif

int HostAndPort::port() const {
    if (hasPort())
        return _port;
    return client::Options::kDbServer;
}

bool HostAndPort::isLocalHost() const {
    return (_host == "localhost" || str::startsWith(_host.c_str(), "127.") || _host == "::1" ||
            _host == "anonymous unix socket" || _host.c_str()[0] == '/'  // unix socket
            );
}

std::string HostAndPort::toString() const {
    StringBuilder ss;
    append(ss);
    return ss.str();
}

void HostAndPort::append(StringBuilder& ss) const {
    // wrap ipv6 addresses in []s for roundtrip-ability
    if (host().find(':') != std::string::npos) {
        ss << '[' << host() << ']';
    } else {
        ss << host();
    }
    ss << ':' << port();
}

bool HostAndPort::empty() const {
    return _host.empty() && _port < 0;
}

Status HostAndPort::initialize(const StringData& s) {
    size_t colonPos = s.rfind(':');
    StringData hostPart = s.substr(0, colonPos);

    // handle ipv6 hostPart (which we require to be wrapped in []s)
    const size_t openBracketPos = s.find('[');
    const size_t closeBracketPos = s.find(']');
    if (openBracketPos != std::string::npos) {
        if (openBracketPos != 0) {
            return Status(ErrorCodes::FailedToParse,
                          str::stream() << "'[' present, but not first character in "
                                        << s.toString());
        }
        if (closeBracketPos == std::string::npos) {
            return Status(ErrorCodes::FailedToParse,
                          str::stream() << "ipv6 address is missing closing ']' in hostname in "
                                        << s.toString());
        }

        hostPart = s.substr(openBracketPos + 1, closeBracketPos - openBracketPos - 1);
        // prevent accidental assignment of port to the value of the final portion of hostPart
        if (colonPos < closeBracketPos) {
            colonPos = std::string::npos;
        } else if (colonPos != closeBracketPos + 1) {
            return Status(ErrorCodes::FailedToParse,
                          str::stream() << "Extraneous characters between ']' and pre-port ':'"
                                        << " in " << s.toString());
        }
    } else if (closeBracketPos != std::string::npos) {
        return Status(ErrorCodes::FailedToParse,
                      str::stream() << "']' present without '[' in " << s.toString());
    } else if (s.find(':') != colonPos) {
        return Status(ErrorCodes::FailedToParse,
                      str::stream() << "More than one ':' detected. If this is an ipv6 address,"
                                    << " it needs to be surrounded by '[' and ']'; "
                                    << s.toString());
    }

    if (hostPart.empty()) {
        return Status(ErrorCodes::FailedToParse,
                      str::stream() << "Empty host component parsing HostAndPort from \""
                                    << escape(s.toString()) << "\"");
    }

    int port;
    if (colonPos != std::string::npos) {
        const StringData portPart = s.substr(colonPos + 1);
        Status status = parseNumberFromStringWithBase(portPart, 10, &port);
        if (!status.isOK()) {
            return status;
        }
        if (port <= 0) {
            return Status(ErrorCodes::FailedToParse,
                          str::stream() << "Port number " << port
                                        << " out of range parsing HostAndPort from \""
                                        << escape(s.toString()) << "\"");
        }
    } else {
        port = -1;
    }
    _host = hostPart.toString();
    _port = port;
    return Status::OK();
}

std::ostream& operator<<(std::ostream& os, const HostAndPort& hp) {
    return os << hp.toString();
}

}  // namespace mongo

MONGO_HASH_NAMESPACE_START
size_t hash<mongo::HostAndPort>::operator()(const mongo::HostAndPort& host) const {
    hash<int> intHasher;
    size_t hash = intHasher(host.port());
    boost::hash_combine(hash, host.host());
    return hash;
}
MONGO_HASH_NAMESPACE_END
