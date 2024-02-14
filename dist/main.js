"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// node_modules/@actions/core/lib/utils.js
var require_utils = __commonJS({
  "node_modules/@actions/core/lib/utils.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.toCommandProperties = exports2.toCommandValue = void 0;
    function toCommandValue(input) {
      if (input === null || input === void 0) {
        return "";
      } else if (typeof input === "string" || input instanceof String) {
        return input;
      }
      return JSON.stringify(input);
    }
    exports2.toCommandValue = toCommandValue;
    function toCommandProperties(annotationProperties) {
      if (!Object.keys(annotationProperties).length) {
        return {};
      }
      return {
        title: annotationProperties.title,
        file: annotationProperties.file,
        line: annotationProperties.startLine,
        endLine: annotationProperties.endLine,
        col: annotationProperties.startColumn,
        endColumn: annotationProperties.endColumn
      };
    }
    exports2.toCommandProperties = toCommandProperties;
  }
});

// node_modules/@actions/core/lib/command.js
var require_command = __commonJS({
  "node_modules/@actions/core/lib/command.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.issue = exports2.issueCommand = void 0;
    var os = __importStar(require("os"));
    var utils_1 = require_utils();
    function issueCommand(command, properties, message) {
      const cmd = new Command(command, properties, message);
      process.stdout.write(cmd.toString() + os.EOL);
    }
    exports2.issueCommand = issueCommand;
    function issue(name, message = "") {
      issueCommand(name, {}, message);
    }
    exports2.issue = issue;
    var CMD_STRING = "::";
    var Command = class {
      constructor(command, properties, message) {
        if (!command) {
          command = "missing.command";
        }
        this.command = command;
        this.properties = properties;
        this.message = message;
      }
      toString() {
        let cmdStr = CMD_STRING + this.command;
        if (this.properties && Object.keys(this.properties).length > 0) {
          cmdStr += " ";
          let first = true;
          for (const key in this.properties) {
            if (this.properties.hasOwnProperty(key)) {
              const val = this.properties[key];
              if (val) {
                if (first) {
                  first = false;
                } else {
                  cmdStr += ",";
                }
                cmdStr += `${key}=${escapeProperty(val)}`;
              }
            }
          }
        }
        cmdStr += `${CMD_STRING}${escapeData(this.message)}`;
        return cmdStr;
      }
    };
    function escapeData(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
    }
    function escapeProperty(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
    }
  }
});

// node_modules/uuid/dist/esm-node/rng.js
function rng() {
  if (poolPtr > rnds8Pool.length - 16) {
    import_crypto.default.randomFillSync(rnds8Pool);
    poolPtr = 0;
  }
  return rnds8Pool.slice(poolPtr, poolPtr += 16);
}
var import_crypto, rnds8Pool, poolPtr;
var init_rng = __esm({
  "node_modules/uuid/dist/esm-node/rng.js"() {
    import_crypto = __toESM(require("crypto"));
    rnds8Pool = new Uint8Array(256);
    poolPtr = rnds8Pool.length;
  }
});

// node_modules/uuid/dist/esm-node/regex.js
var regex_default;
var init_regex = __esm({
  "node_modules/uuid/dist/esm-node/regex.js"() {
    regex_default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
  }
});

// node_modules/uuid/dist/esm-node/validate.js
function validate(uuid) {
  return typeof uuid === "string" && regex_default.test(uuid);
}
var validate_default;
var init_validate = __esm({
  "node_modules/uuid/dist/esm-node/validate.js"() {
    init_regex();
    validate_default = validate;
  }
});

// node_modules/uuid/dist/esm-node/stringify.js
function stringify(arr, offset = 0) {
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
  if (!validate_default(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
var byteToHex, stringify_default;
var init_stringify = __esm({
  "node_modules/uuid/dist/esm-node/stringify.js"() {
    init_validate();
    byteToHex = [];
    for (let i = 0; i < 256; ++i) {
      byteToHex.push((i + 256).toString(16).substr(1));
    }
    stringify_default = stringify;
  }
});

// node_modules/uuid/dist/esm-node/v1.js
function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== void 0 ? options.clockseq : _clockseq;
  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || rng)();
    if (node == null) {
      node = _nodeId = [seedBytes[0] | 1, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }
    if (clockseq == null) {
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 16383;
    }
  }
  let msecs = options.msecs !== void 0 ? options.msecs : Date.now();
  let nsecs = options.nsecs !== void 0 ? options.nsecs : _lastNSecs + 1;
  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 1e4;
  if (dt < 0 && options.clockseq === void 0) {
    clockseq = clockseq + 1 & 16383;
  }
  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === void 0) {
    nsecs = 0;
  }
  if (nsecs >= 1e4) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }
  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq;
  msecs += 122192928e5;
  const tl = ((msecs & 268435455) * 1e4 + nsecs) % 4294967296;
  b[i++] = tl >>> 24 & 255;
  b[i++] = tl >>> 16 & 255;
  b[i++] = tl >>> 8 & 255;
  b[i++] = tl & 255;
  const tmh = msecs / 4294967296 * 1e4 & 268435455;
  b[i++] = tmh >>> 8 & 255;
  b[i++] = tmh & 255;
  b[i++] = tmh >>> 24 & 15 | 16;
  b[i++] = tmh >>> 16 & 255;
  b[i++] = clockseq >>> 8 | 128;
  b[i++] = clockseq & 255;
  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }
  return buf || stringify_default(b);
}
var _nodeId, _clockseq, _lastMSecs, _lastNSecs, v1_default;
var init_v1 = __esm({
  "node_modules/uuid/dist/esm-node/v1.js"() {
    init_rng();
    init_stringify();
    _lastMSecs = 0;
    _lastNSecs = 0;
    v1_default = v1;
  }
});

// node_modules/uuid/dist/esm-node/parse.js
function parse(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  let v;
  const arr = new Uint8Array(16);
  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 255;
  arr[2] = v >>> 8 & 255;
  arr[3] = v & 255;
  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 255;
  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 255;
  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 255;
  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 1099511627776 & 255;
  arr[11] = v / 4294967296 & 255;
  arr[12] = v >>> 24 & 255;
  arr[13] = v >>> 16 & 255;
  arr[14] = v >>> 8 & 255;
  arr[15] = v & 255;
  return arr;
}
var parse_default;
var init_parse = __esm({
  "node_modules/uuid/dist/esm-node/parse.js"() {
    init_validate();
    parse_default = parse;
  }
});

// node_modules/uuid/dist/esm-node/v35.js
function stringToBytes(str) {
  str = unescape(encodeURIComponent(str));
  const bytes = [];
  for (let i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }
  return bytes;
}
function v35_default(name, version2, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === "string") {
      value = stringToBytes(value);
    }
    if (typeof namespace === "string") {
      namespace = parse_default(namespace);
    }
    if (namespace.length !== 16) {
      throw TypeError("Namespace must be array-like (16 iterable integer values, 0-255)");
    }
    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 15 | version2;
    bytes[8] = bytes[8] & 63 | 128;
    if (buf) {
      offset = offset || 0;
      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }
      return buf;
    }
    return stringify_default(bytes);
  }
  try {
    generateUUID.name = name;
  } catch (err) {
  }
  generateUUID.DNS = DNS;
  generateUUID.URL = URL2;
  return generateUUID;
}
var DNS, URL2;
var init_v35 = __esm({
  "node_modules/uuid/dist/esm-node/v35.js"() {
    init_stringify();
    init_parse();
    DNS = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    URL2 = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
  }
});

// node_modules/uuid/dist/esm-node/md5.js
function md5(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return import_crypto2.default.createHash("md5").update(bytes).digest();
}
var import_crypto2, md5_default;
var init_md5 = __esm({
  "node_modules/uuid/dist/esm-node/md5.js"() {
    import_crypto2 = __toESM(require("crypto"));
    md5_default = md5;
  }
});

// node_modules/uuid/dist/esm-node/v3.js
var v3, v3_default;
var init_v3 = __esm({
  "node_modules/uuid/dist/esm-node/v3.js"() {
    init_v35();
    init_md5();
    v3 = v35_default("v3", 48, md5_default);
    v3_default = v3;
  }
});

// node_modules/uuid/dist/esm-node/v4.js
function v4(options, buf, offset) {
  options = options || {};
  const rnds = options.random || (options.rng || rng)();
  rnds[6] = rnds[6] & 15 | 64;
  rnds[8] = rnds[8] & 63 | 128;
  if (buf) {
    offset = offset || 0;
    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }
    return buf;
  }
  return stringify_default(rnds);
}
var v4_default;
var init_v4 = __esm({
  "node_modules/uuid/dist/esm-node/v4.js"() {
    init_rng();
    init_stringify();
    v4_default = v4;
  }
});

// node_modules/uuid/dist/esm-node/sha1.js
function sha1(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return import_crypto3.default.createHash("sha1").update(bytes).digest();
}
var import_crypto3, sha1_default;
var init_sha1 = __esm({
  "node_modules/uuid/dist/esm-node/sha1.js"() {
    import_crypto3 = __toESM(require("crypto"));
    sha1_default = sha1;
  }
});

// node_modules/uuid/dist/esm-node/v5.js
var v5, v5_default;
var init_v5 = __esm({
  "node_modules/uuid/dist/esm-node/v5.js"() {
    init_v35();
    init_sha1();
    v5 = v35_default("v5", 80, sha1_default);
    v5_default = v5;
  }
});

// node_modules/uuid/dist/esm-node/nil.js
var nil_default;
var init_nil = __esm({
  "node_modules/uuid/dist/esm-node/nil.js"() {
    nil_default = "00000000-0000-0000-0000-000000000000";
  }
});

// node_modules/uuid/dist/esm-node/version.js
function version(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  return parseInt(uuid.substr(14, 1), 16);
}
var version_default;
var init_version = __esm({
  "node_modules/uuid/dist/esm-node/version.js"() {
    init_validate();
    version_default = version;
  }
});

// node_modules/uuid/dist/esm-node/index.js
var esm_node_exports = {};
__export(esm_node_exports, {
  NIL: () => nil_default,
  parse: () => parse_default,
  stringify: () => stringify_default,
  v1: () => v1_default,
  v3: () => v3_default,
  v4: () => v4_default,
  v5: () => v5_default,
  validate: () => validate_default,
  version: () => version_default
});
var init_esm_node = __esm({
  "node_modules/uuid/dist/esm-node/index.js"() {
    init_v1();
    init_v3();
    init_v4();
    init_v5();
    init_nil();
    init_version();
    init_validate();
    init_stringify();
    init_parse();
  }
});

// node_modules/@actions/core/lib/file-command.js
var require_file_command = __commonJS({
  "node_modules/@actions/core/lib/file-command.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.prepareKeyValueMessage = exports2.issueFileCommand = void 0;
    var fs2 = __importStar(require("fs"));
    var os = __importStar(require("os"));
    var uuid_1 = (init_esm_node(), __toCommonJS(esm_node_exports));
    var utils_1 = require_utils();
    function issueFileCommand(command, message) {
      const filePath = process.env[`GITHUB_${command}`];
      if (!filePath) {
        throw new Error(`Unable to find environment variable for file command ${command}`);
      }
      if (!fs2.existsSync(filePath)) {
        throw new Error(`Missing file at path: ${filePath}`);
      }
      fs2.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os.EOL}`, {
        encoding: "utf8"
      });
    }
    exports2.issueFileCommand = issueFileCommand;
    function prepareKeyValueMessage(key, value) {
      const delimiter = `ghadelimiter_${uuid_1.v4()}`;
      const convertedValue = utils_1.toCommandValue(value);
      if (key.includes(delimiter)) {
        throw new Error(`Unexpected input: name should not contain the delimiter "${delimiter}"`);
      }
      if (convertedValue.includes(delimiter)) {
        throw new Error(`Unexpected input: value should not contain the delimiter "${delimiter}"`);
      }
      return `${key}<<${delimiter}${os.EOL}${convertedValue}${os.EOL}${delimiter}`;
    }
    exports2.prepareKeyValueMessage = prepareKeyValueMessage;
  }
});

// node_modules/@actions/http-client/lib/proxy.js
var require_proxy = __commonJS({
  "node_modules/@actions/http-client/lib/proxy.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.checkBypass = exports2.getProxyUrl = void 0;
    function getProxyUrl(reqUrl) {
      const usingSsl = reqUrl.protocol === "https:";
      if (checkBypass(reqUrl)) {
        return void 0;
      }
      const proxyVar = (() => {
        if (usingSsl) {
          return process.env["https_proxy"] || process.env["HTTPS_PROXY"];
        } else {
          return process.env["http_proxy"] || process.env["HTTP_PROXY"];
        }
      })();
      if (proxyVar) {
        return new URL(proxyVar);
      } else {
        return void 0;
      }
    }
    exports2.getProxyUrl = getProxyUrl;
    function checkBypass(reqUrl) {
      if (!reqUrl.hostname) {
        return false;
      }
      const noProxy = process.env["no_proxy"] || process.env["NO_PROXY"] || "";
      if (!noProxy) {
        return false;
      }
      let reqPort;
      if (reqUrl.port) {
        reqPort = Number(reqUrl.port);
      } else if (reqUrl.protocol === "http:") {
        reqPort = 80;
      } else if (reqUrl.protocol === "https:") {
        reqPort = 443;
      }
      const upperReqHosts = [reqUrl.hostname.toUpperCase()];
      if (typeof reqPort === "number") {
        upperReqHosts.push(`${upperReqHosts[0]}:${reqPort}`);
      }
      for (const upperNoProxyItem of noProxy.split(",").map((x) => x.trim().toUpperCase()).filter((x) => x)) {
        if (upperReqHosts.some((x) => x === upperNoProxyItem)) {
          return true;
        }
      }
      return false;
    }
    exports2.checkBypass = checkBypass;
  }
});

// node_modules/tunnel/lib/tunnel.js
var require_tunnel = __commonJS({
  "node_modules/tunnel/lib/tunnel.js"(exports2) {
    "use strict";
    var net = require("net");
    var tls = require("tls");
    var http = require("http");
    var https = require("https");
    var events = require("events");
    var assert = require("assert");
    var util = require("util");
    exports2.httpOverHttp = httpOverHttp;
    exports2.httpsOverHttp = httpsOverHttp;
    exports2.httpOverHttps = httpOverHttps;
    exports2.httpsOverHttps = httpsOverHttps;
    function httpOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      return agent;
    }
    function httpsOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function httpOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      return agent;
    }
    function httpsOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function TunnelingAgent(options) {
      var self2 = this;
      self2.options = options || {};
      self2.proxyOptions = self2.options.proxy || {};
      self2.maxSockets = self2.options.maxSockets || http.Agent.defaultMaxSockets;
      self2.requests = [];
      self2.sockets = [];
      self2.on("free", function onFree(socket, host, port, localAddress) {
        var options2 = toOptions(host, port, localAddress);
        for (var i = 0, len = self2.requests.length; i < len; ++i) {
          var pending = self2.requests[i];
          if (pending.host === options2.host && pending.port === options2.port) {
            self2.requests.splice(i, 1);
            pending.request.onSocket(socket);
            return;
          }
        }
        socket.destroy();
        self2.removeSocket(socket);
      });
    }
    util.inherits(TunnelingAgent, events.EventEmitter);
    TunnelingAgent.prototype.addRequest = function addRequest(req, host, port, localAddress) {
      var self2 = this;
      var options = mergeOptions({ request: req }, self2.options, toOptions(host, port, localAddress));
      if (self2.sockets.length >= this.maxSockets) {
        self2.requests.push(options);
        return;
      }
      self2.createSocket(options, function(socket) {
        socket.on("free", onFree);
        socket.on("close", onCloseOrRemove);
        socket.on("agentRemove", onCloseOrRemove);
        req.onSocket(socket);
        function onFree() {
          self2.emit("free", socket, options);
        }
        function onCloseOrRemove(err) {
          self2.removeSocket(socket);
          socket.removeListener("free", onFree);
          socket.removeListener("close", onCloseOrRemove);
          socket.removeListener("agentRemove", onCloseOrRemove);
        }
      });
    };
    TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
      var self2 = this;
      var placeholder = {};
      self2.sockets.push(placeholder);
      var connectOptions = mergeOptions({}, self2.proxyOptions, {
        method: "CONNECT",
        path: options.host + ":" + options.port,
        agent: false,
        headers: {
          host: options.host + ":" + options.port
        }
      });
      if (options.localAddress) {
        connectOptions.localAddress = options.localAddress;
      }
      if (connectOptions.proxyAuth) {
        connectOptions.headers = connectOptions.headers || {};
        connectOptions.headers["Proxy-Authorization"] = "Basic " + new Buffer(connectOptions.proxyAuth).toString("base64");
      }
      debug2("making CONNECT request");
      var connectReq = self2.request(connectOptions);
      connectReq.useChunkedEncodingByDefault = false;
      connectReq.once("response", onResponse);
      connectReq.once("upgrade", onUpgrade);
      connectReq.once("connect", onConnect);
      connectReq.once("error", onError);
      connectReq.end();
      function onResponse(res) {
        res.upgrade = true;
      }
      function onUpgrade(res, socket, head) {
        process.nextTick(function() {
          onConnect(res, socket, head);
        });
      }
      function onConnect(res, socket, head) {
        connectReq.removeAllListeners();
        socket.removeAllListeners();
        if (res.statusCode !== 200) {
          debug2(
            "tunneling socket could not be established, statusCode=%d",
            res.statusCode
          );
          socket.destroy();
          var error = new Error("tunneling socket could not be established, statusCode=" + res.statusCode);
          error.code = "ECONNRESET";
          options.request.emit("error", error);
          self2.removeSocket(placeholder);
          return;
        }
        if (head.length > 0) {
          debug2("got illegal response body from proxy");
          socket.destroy();
          var error = new Error("got illegal response body from proxy");
          error.code = "ECONNRESET";
          options.request.emit("error", error);
          self2.removeSocket(placeholder);
          return;
        }
        debug2("tunneling connection has established");
        self2.sockets[self2.sockets.indexOf(placeholder)] = socket;
        return cb(socket);
      }
      function onError(cause) {
        connectReq.removeAllListeners();
        debug2(
          "tunneling socket could not be established, cause=%s\n",
          cause.message,
          cause.stack
        );
        var error = new Error("tunneling socket could not be established, cause=" + cause.message);
        error.code = "ECONNRESET";
        options.request.emit("error", error);
        self2.removeSocket(placeholder);
      }
    };
    TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
      var pos = this.sockets.indexOf(socket);
      if (pos === -1) {
        return;
      }
      this.sockets.splice(pos, 1);
      var pending = this.requests.shift();
      if (pending) {
        this.createSocket(pending, function(socket2) {
          pending.request.onSocket(socket2);
        });
      }
    };
    function createSecureSocket(options, cb) {
      var self2 = this;
      TunnelingAgent.prototype.createSocket.call(self2, options, function(socket) {
        var hostHeader = options.request.getHeader("host");
        var tlsOptions = mergeOptions({}, self2.options, {
          socket,
          servername: hostHeader ? hostHeader.replace(/:.*$/, "") : options.host
        });
        var secureSocket = tls.connect(0, tlsOptions);
        self2.sockets[self2.sockets.indexOf(socket)] = secureSocket;
        cb(secureSocket);
      });
    }
    function toOptions(host, port, localAddress) {
      if (typeof host === "string") {
        return {
          host,
          port,
          localAddress
        };
      }
      return host;
    }
    function mergeOptions(target) {
      for (var i = 1, len = arguments.length; i < len; ++i) {
        var overrides = arguments[i];
        if (typeof overrides === "object") {
          var keys = Object.keys(overrides);
          for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
            var k = keys[j];
            if (overrides[k] !== void 0) {
              target[k] = overrides[k];
            }
          }
        }
      }
      return target;
    }
    var debug2;
    if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
      debug2 = function() {
        var args = Array.prototype.slice.call(arguments);
        if (typeof args[0] === "string") {
          args[0] = "TUNNEL: " + args[0];
        } else {
          args.unshift("TUNNEL:");
        }
        console.error.apply(console, args);
      };
    } else {
      debug2 = function() {
      };
    }
    exports2.debug = debug2;
  }
});

// node_modules/tunnel/index.js
var require_tunnel2 = __commonJS({
  "node_modules/tunnel/index.js"(exports2, module2) {
    module2.exports = require_tunnel();
  }
});

// node_modules/@actions/http-client/lib/index.js
var require_lib = __commonJS({
  "node_modules/@actions/http-client/lib/index.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.HttpClient = exports2.isHttps = exports2.HttpClientResponse = exports2.HttpClientError = exports2.getProxyUrl = exports2.MediaTypes = exports2.Headers = exports2.HttpCodes = void 0;
    var http = __importStar(require("http"));
    var https = __importStar(require("https"));
    var pm = __importStar(require_proxy());
    var tunnel = __importStar(require_tunnel2());
    var HttpCodes;
    (function(HttpCodes2) {
      HttpCodes2[HttpCodes2["OK"] = 200] = "OK";
      HttpCodes2[HttpCodes2["MultipleChoices"] = 300] = "MultipleChoices";
      HttpCodes2[HttpCodes2["MovedPermanently"] = 301] = "MovedPermanently";
      HttpCodes2[HttpCodes2["ResourceMoved"] = 302] = "ResourceMoved";
      HttpCodes2[HttpCodes2["SeeOther"] = 303] = "SeeOther";
      HttpCodes2[HttpCodes2["NotModified"] = 304] = "NotModified";
      HttpCodes2[HttpCodes2["UseProxy"] = 305] = "UseProxy";
      HttpCodes2[HttpCodes2["SwitchProxy"] = 306] = "SwitchProxy";
      HttpCodes2[HttpCodes2["TemporaryRedirect"] = 307] = "TemporaryRedirect";
      HttpCodes2[HttpCodes2["PermanentRedirect"] = 308] = "PermanentRedirect";
      HttpCodes2[HttpCodes2["BadRequest"] = 400] = "BadRequest";
      HttpCodes2[HttpCodes2["Unauthorized"] = 401] = "Unauthorized";
      HttpCodes2[HttpCodes2["PaymentRequired"] = 402] = "PaymentRequired";
      HttpCodes2[HttpCodes2["Forbidden"] = 403] = "Forbidden";
      HttpCodes2[HttpCodes2["NotFound"] = 404] = "NotFound";
      HttpCodes2[HttpCodes2["MethodNotAllowed"] = 405] = "MethodNotAllowed";
      HttpCodes2[HttpCodes2["NotAcceptable"] = 406] = "NotAcceptable";
      HttpCodes2[HttpCodes2["ProxyAuthenticationRequired"] = 407] = "ProxyAuthenticationRequired";
      HttpCodes2[HttpCodes2["RequestTimeout"] = 408] = "RequestTimeout";
      HttpCodes2[HttpCodes2["Conflict"] = 409] = "Conflict";
      HttpCodes2[HttpCodes2["Gone"] = 410] = "Gone";
      HttpCodes2[HttpCodes2["TooManyRequests"] = 429] = "TooManyRequests";
      HttpCodes2[HttpCodes2["InternalServerError"] = 500] = "InternalServerError";
      HttpCodes2[HttpCodes2["NotImplemented"] = 501] = "NotImplemented";
      HttpCodes2[HttpCodes2["BadGateway"] = 502] = "BadGateway";
      HttpCodes2[HttpCodes2["ServiceUnavailable"] = 503] = "ServiceUnavailable";
      HttpCodes2[HttpCodes2["GatewayTimeout"] = 504] = "GatewayTimeout";
    })(HttpCodes = exports2.HttpCodes || (exports2.HttpCodes = {}));
    var Headers;
    (function(Headers2) {
      Headers2["Accept"] = "accept";
      Headers2["ContentType"] = "content-type";
    })(Headers = exports2.Headers || (exports2.Headers = {}));
    var MediaTypes;
    (function(MediaTypes2) {
      MediaTypes2["ApplicationJson"] = "application/json";
    })(MediaTypes = exports2.MediaTypes || (exports2.MediaTypes = {}));
    function getProxyUrl(serverUrl) {
      const proxyUrl = pm.getProxyUrl(new URL(serverUrl));
      return proxyUrl ? proxyUrl.href : "";
    }
    exports2.getProxyUrl = getProxyUrl;
    var HttpRedirectCodes = [
      HttpCodes.MovedPermanently,
      HttpCodes.ResourceMoved,
      HttpCodes.SeeOther,
      HttpCodes.TemporaryRedirect,
      HttpCodes.PermanentRedirect
    ];
    var HttpResponseRetryCodes = [
      HttpCodes.BadGateway,
      HttpCodes.ServiceUnavailable,
      HttpCodes.GatewayTimeout
    ];
    var RetryableHttpVerbs = ["OPTIONS", "GET", "DELETE", "HEAD"];
    var ExponentialBackoffCeiling = 10;
    var ExponentialBackoffTimeSlice = 5;
    var HttpClientError = class _HttpClientError extends Error {
      constructor(message, statusCode) {
        super(message);
        this.name = "HttpClientError";
        this.statusCode = statusCode;
        Object.setPrototypeOf(this, _HttpClientError.prototype);
      }
    };
    exports2.HttpClientError = HttpClientError;
    var HttpClientResponse = class {
      constructor(message) {
        this.message = message;
      }
      readBody() {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve) => __awaiter(this, void 0, void 0, function* () {
            let output = Buffer.alloc(0);
            this.message.on("data", (chunk) => {
              output = Buffer.concat([output, chunk]);
            });
            this.message.on("end", () => {
              resolve(output.toString());
            });
          }));
        });
      }
    };
    exports2.HttpClientResponse = HttpClientResponse;
    function isHttps(requestUrl) {
      const parsedUrl = new URL(requestUrl);
      return parsedUrl.protocol === "https:";
    }
    exports2.isHttps = isHttps;
    var HttpClient = class {
      constructor(userAgent, handlers, requestOptions) {
        this._ignoreSslError = false;
        this._allowRedirects = true;
        this._allowRedirectDowngrade = false;
        this._maxRedirects = 50;
        this._allowRetries = false;
        this._maxRetries = 1;
        this._keepAlive = false;
        this._disposed = false;
        this.userAgent = userAgent;
        this.handlers = handlers || [];
        this.requestOptions = requestOptions;
        if (requestOptions) {
          if (requestOptions.ignoreSslError != null) {
            this._ignoreSslError = requestOptions.ignoreSslError;
          }
          this._socketTimeout = requestOptions.socketTimeout;
          if (requestOptions.allowRedirects != null) {
            this._allowRedirects = requestOptions.allowRedirects;
          }
          if (requestOptions.allowRedirectDowngrade != null) {
            this._allowRedirectDowngrade = requestOptions.allowRedirectDowngrade;
          }
          if (requestOptions.maxRedirects != null) {
            this._maxRedirects = Math.max(requestOptions.maxRedirects, 0);
          }
          if (requestOptions.keepAlive != null) {
            this._keepAlive = requestOptions.keepAlive;
          }
          if (requestOptions.allowRetries != null) {
            this._allowRetries = requestOptions.allowRetries;
          }
          if (requestOptions.maxRetries != null) {
            this._maxRetries = requestOptions.maxRetries;
          }
        }
      }
      options(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("OPTIONS", requestUrl, null, additionalHeaders || {});
        });
      }
      get(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("GET", requestUrl, null, additionalHeaders || {});
        });
      }
      del(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("DELETE", requestUrl, null, additionalHeaders || {});
        });
      }
      post(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("POST", requestUrl, data, additionalHeaders || {});
        });
      }
      patch(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PATCH", requestUrl, data, additionalHeaders || {});
        });
      }
      put(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PUT", requestUrl, data, additionalHeaders || {});
        });
      }
      head(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("HEAD", requestUrl, null, additionalHeaders || {});
        });
      }
      sendStream(verb, requestUrl, stream, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request(verb, requestUrl, stream, additionalHeaders);
        });
      }
      /**
       * Gets a typed object from an endpoint
       * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
       */
      getJson(requestUrl, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          const res = yield this.get(requestUrl, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      postJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.post(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.put(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      patchJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.patch(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      /**
       * Makes a raw http request.
       * All other methods such as get, post, patch, and request ultimately call this.
       * Prefer get, del, post and patch
       */
      request(verb, requestUrl, data, headers) {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._disposed) {
            throw new Error("Client has already been disposed.");
          }
          const parsedUrl = new URL(requestUrl);
          let info = this._prepareRequest(verb, parsedUrl, headers);
          const maxTries = this._allowRetries && RetryableHttpVerbs.includes(verb) ? this._maxRetries + 1 : 1;
          let numTries = 0;
          let response;
          do {
            response = yield this.requestRaw(info, data);
            if (response && response.message && response.message.statusCode === HttpCodes.Unauthorized) {
              let authenticationHandler;
              for (const handler of this.handlers) {
                if (handler.canHandleAuthentication(response)) {
                  authenticationHandler = handler;
                  break;
                }
              }
              if (authenticationHandler) {
                return authenticationHandler.handleAuthentication(this, info, data);
              } else {
                return response;
              }
            }
            let redirectsRemaining = this._maxRedirects;
            while (response.message.statusCode && HttpRedirectCodes.includes(response.message.statusCode) && this._allowRedirects && redirectsRemaining > 0) {
              const redirectUrl = response.message.headers["location"];
              if (!redirectUrl) {
                break;
              }
              const parsedRedirectUrl = new URL(redirectUrl);
              if (parsedUrl.protocol === "https:" && parsedUrl.protocol !== parsedRedirectUrl.protocol && !this._allowRedirectDowngrade) {
                throw new Error("Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.");
              }
              yield response.readBody();
              if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
                for (const header in headers) {
                  if (header.toLowerCase() === "authorization") {
                    delete headers[header];
                  }
                }
              }
              info = this._prepareRequest(verb, parsedRedirectUrl, headers);
              response = yield this.requestRaw(info, data);
              redirectsRemaining--;
            }
            if (!response.message.statusCode || !HttpResponseRetryCodes.includes(response.message.statusCode)) {
              return response;
            }
            numTries += 1;
            if (numTries < maxTries) {
              yield response.readBody();
              yield this._performExponentialBackoff(numTries);
            }
          } while (numTries < maxTries);
          return response;
        });
      }
      /**
       * Needs to be called if keepAlive is set to true in request options.
       */
      dispose() {
        if (this._agent) {
          this._agent.destroy();
        }
        this._disposed = true;
      }
      /**
       * Raw request.
       * @param info
       * @param data
       */
      requestRaw(info, data) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve, reject) => {
            function callbackForResult(err, res) {
              if (err) {
                reject(err);
              } else if (!res) {
                reject(new Error("Unknown error"));
              } else {
                resolve(res);
              }
            }
            this.requestRawWithCallback(info, data, callbackForResult);
          });
        });
      }
      /**
       * Raw request with callback.
       * @param info
       * @param data
       * @param onResult
       */
      requestRawWithCallback(info, data, onResult) {
        if (typeof data === "string") {
          if (!info.options.headers) {
            info.options.headers = {};
          }
          info.options.headers["Content-Length"] = Buffer.byteLength(data, "utf8");
        }
        let callbackCalled = false;
        function handleResult(err, res) {
          if (!callbackCalled) {
            callbackCalled = true;
            onResult(err, res);
          }
        }
        const req = info.httpModule.request(info.options, (msg) => {
          const res = new HttpClientResponse(msg);
          handleResult(void 0, res);
        });
        let socket;
        req.on("socket", (sock) => {
          socket = sock;
        });
        req.setTimeout(this._socketTimeout || 3 * 6e4, () => {
          if (socket) {
            socket.end();
          }
          handleResult(new Error(`Request timeout: ${info.options.path}`));
        });
        req.on("error", function(err) {
          handleResult(err);
        });
        if (data && typeof data === "string") {
          req.write(data, "utf8");
        }
        if (data && typeof data !== "string") {
          data.on("close", function() {
            req.end();
          });
          data.pipe(req);
        } else {
          req.end();
        }
      }
      /**
       * Gets an http agent. This function is useful when you need an http agent that handles
       * routing through a proxy server - depending upon the url and proxy environment variables.
       * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
       */
      getAgent(serverUrl) {
        const parsedUrl = new URL(serverUrl);
        return this._getAgent(parsedUrl);
      }
      _prepareRequest(method, requestUrl, headers) {
        const info = {};
        info.parsedUrl = requestUrl;
        const usingSsl = info.parsedUrl.protocol === "https:";
        info.httpModule = usingSsl ? https : http;
        const defaultPort = usingSsl ? 443 : 80;
        info.options = {};
        info.options.host = info.parsedUrl.hostname;
        info.options.port = info.parsedUrl.port ? parseInt(info.parsedUrl.port) : defaultPort;
        info.options.path = (info.parsedUrl.pathname || "") + (info.parsedUrl.search || "");
        info.options.method = method;
        info.options.headers = this._mergeHeaders(headers);
        if (this.userAgent != null) {
          info.options.headers["user-agent"] = this.userAgent;
        }
        info.options.agent = this._getAgent(info.parsedUrl);
        if (this.handlers) {
          for (const handler of this.handlers) {
            handler.prepareRequest(info.options);
          }
        }
        return info;
      }
      _mergeHeaders(headers) {
        if (this.requestOptions && this.requestOptions.headers) {
          return Object.assign({}, lowercaseKeys(this.requestOptions.headers), lowercaseKeys(headers || {}));
        }
        return lowercaseKeys(headers || {});
      }
      _getExistingOrDefaultHeader(additionalHeaders, header, _default) {
        let clientHeader;
        if (this.requestOptions && this.requestOptions.headers) {
          clientHeader = lowercaseKeys(this.requestOptions.headers)[header];
        }
        return additionalHeaders[header] || clientHeader || _default;
      }
      _getAgent(parsedUrl) {
        let agent;
        const proxyUrl = pm.getProxyUrl(parsedUrl);
        const useProxy = proxyUrl && proxyUrl.hostname;
        if (this._keepAlive && useProxy) {
          agent = this._proxyAgent;
        }
        if (this._keepAlive && !useProxy) {
          agent = this._agent;
        }
        if (agent) {
          return agent;
        }
        const usingSsl = parsedUrl.protocol === "https:";
        let maxSockets = 100;
        if (this.requestOptions) {
          maxSockets = this.requestOptions.maxSockets || http.globalAgent.maxSockets;
        }
        if (proxyUrl && proxyUrl.hostname) {
          const agentOptions = {
            maxSockets,
            keepAlive: this._keepAlive,
            proxy: Object.assign(Object.assign({}, (proxyUrl.username || proxyUrl.password) && {
              proxyAuth: `${proxyUrl.username}:${proxyUrl.password}`
            }), { host: proxyUrl.hostname, port: proxyUrl.port })
          };
          let tunnelAgent;
          const overHttps = proxyUrl.protocol === "https:";
          if (usingSsl) {
            tunnelAgent = overHttps ? tunnel.httpsOverHttps : tunnel.httpsOverHttp;
          } else {
            tunnelAgent = overHttps ? tunnel.httpOverHttps : tunnel.httpOverHttp;
          }
          agent = tunnelAgent(agentOptions);
          this._proxyAgent = agent;
        }
        if (this._keepAlive && !agent) {
          const options = { keepAlive: this._keepAlive, maxSockets };
          agent = usingSsl ? new https.Agent(options) : new http.Agent(options);
          this._agent = agent;
        }
        if (!agent) {
          agent = usingSsl ? https.globalAgent : http.globalAgent;
        }
        if (usingSsl && this._ignoreSslError) {
          agent.options = Object.assign(agent.options || {}, {
            rejectUnauthorized: false
          });
        }
        return agent;
      }
      _performExponentialBackoff(retryNumber) {
        return __awaiter(this, void 0, void 0, function* () {
          retryNumber = Math.min(ExponentialBackoffCeiling, retryNumber);
          const ms = ExponentialBackoffTimeSlice * Math.pow(2, retryNumber);
          return new Promise((resolve) => setTimeout(() => resolve(), ms));
        });
      }
      _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve, reject) => __awaiter(this, void 0, void 0, function* () {
            const statusCode = res.message.statusCode || 0;
            const response = {
              statusCode,
              result: null,
              headers: {}
            };
            if (statusCode === HttpCodes.NotFound) {
              resolve(response);
            }
            function dateTimeDeserializer(key, value) {
              if (typeof value === "string") {
                const a = new Date(value);
                if (!isNaN(a.valueOf())) {
                  return a;
                }
              }
              return value;
            }
            let obj;
            let contents;
            try {
              contents = yield res.readBody();
              if (contents && contents.length > 0) {
                if (options && options.deserializeDates) {
                  obj = JSON.parse(contents, dateTimeDeserializer);
                } else {
                  obj = JSON.parse(contents);
                }
                response.result = obj;
              }
              response.headers = res.message.headers;
            } catch (err) {
            }
            if (statusCode > 299) {
              let msg;
              if (obj && obj.message) {
                msg = obj.message;
              } else if (contents && contents.length > 0) {
                msg = contents;
              } else {
                msg = `Failed request: (${statusCode})`;
              }
              const err = new HttpClientError(msg, statusCode);
              err.result = response.result;
              reject(err);
            } else {
              resolve(response);
            }
          }));
        });
      }
    };
    exports2.HttpClient = HttpClient;
    var lowercaseKeys = (obj) => Object.keys(obj).reduce((c, k) => (c[k.toLowerCase()] = obj[k], c), {});
  }
});

// node_modules/@actions/http-client/lib/auth.js
var require_auth = __commonJS({
  "node_modules/@actions/http-client/lib/auth.js"(exports2) {
    "use strict";
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.PersonalAccessTokenCredentialHandler = exports2.BearerCredentialHandler = exports2.BasicCredentialHandler = void 0;
    var BasicCredentialHandler = class {
      constructor(username, password) {
        this.username = username;
        this.password = password;
      }
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports2.BasicCredentialHandler = BasicCredentialHandler;
    var BearerCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Bearer ${this.token}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports2.BearerCredentialHandler = BearerCredentialHandler;
    var PersonalAccessTokenCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`PAT:${this.token}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports2.PersonalAccessTokenCredentialHandler = PersonalAccessTokenCredentialHandler;
  }
});

// node_modules/@actions/core/lib/oidc-utils.js
var require_oidc_utils = __commonJS({
  "node_modules/@actions/core/lib/oidc-utils.js"(exports2) {
    "use strict";
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.OidcClient = void 0;
    var http_client_1 = require_lib();
    var auth_1 = require_auth();
    var core_1 = require_core();
    var OidcClient = class _OidcClient {
      static createHttpClient(allowRetry = true, maxRetry = 10) {
        const requestOptions = {
          allowRetries: allowRetry,
          maxRetries: maxRetry
        };
        return new http_client_1.HttpClient("actions/oidc-client", [new auth_1.BearerCredentialHandler(_OidcClient.getRequestToken())], requestOptions);
      }
      static getRequestToken() {
        const token = process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"];
        if (!token) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable");
        }
        return token;
      }
      static getIDTokenUrl() {
        const runtimeUrl = process.env["ACTIONS_ID_TOKEN_REQUEST_URL"];
        if (!runtimeUrl) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable");
        }
        return runtimeUrl;
      }
      static getCall(id_token_url) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
          const httpclient = _OidcClient.createHttpClient();
          const res = yield httpclient.getJson(id_token_url).catch((error) => {
            throw new Error(`Failed to get ID Token. 
 
        Error Code : ${error.statusCode}
 
        Error Message: ${error.message}`);
          });
          const id_token = (_a = res.result) === null || _a === void 0 ? void 0 : _a.value;
          if (!id_token) {
            throw new Error("Response json body do not have ID Token field");
          }
          return id_token;
        });
      }
      static getIDToken(audience) {
        return __awaiter(this, void 0, void 0, function* () {
          try {
            let id_token_url = _OidcClient.getIDTokenUrl();
            if (audience) {
              const encodedAudience = encodeURIComponent(audience);
              id_token_url = `${id_token_url}&audience=${encodedAudience}`;
            }
            core_1.debug(`ID token url is ${id_token_url}`);
            const id_token = yield _OidcClient.getCall(id_token_url);
            core_1.setSecret(id_token);
            return id_token;
          } catch (error) {
            throw new Error(`Error message: ${error.message}`);
          }
        });
      }
    };
    exports2.OidcClient = OidcClient;
  }
});

// node_modules/@actions/core/lib/summary.js
var require_summary = __commonJS({
  "node_modules/@actions/core/lib/summary.js"(exports2) {
    "use strict";
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.summary = exports2.markdownSummary = exports2.SUMMARY_DOCS_URL = exports2.SUMMARY_ENV_VAR = void 0;
    var os_1 = require("os");
    var fs_1 = require("fs");
    var { access, appendFile, writeFile } = fs_1.promises;
    exports2.SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY";
    exports2.SUMMARY_DOCS_URL = "https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary";
    var Summary = class {
      constructor() {
        this._buffer = "";
      }
      /**
       * Finds the summary file path from the environment, rejects if env var is not found or file does not exist
       * Also checks r/w permissions.
       *
       * @returns step summary file path
       */
      filePath() {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._filePath) {
            return this._filePath;
          }
          const pathFromEnv = process.env[exports2.SUMMARY_ENV_VAR];
          if (!pathFromEnv) {
            throw new Error(`Unable to find environment variable for $${exports2.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
          }
          try {
            yield access(pathFromEnv, fs_1.constants.R_OK | fs_1.constants.W_OK);
          } catch (_a) {
            throw new Error(`Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`);
          }
          this._filePath = pathFromEnv;
          return this._filePath;
        });
      }
      /**
       * Wraps content in an HTML tag, adding any HTML attributes
       *
       * @param {string} tag HTML tag to wrap
       * @param {string | null} content content within the tag
       * @param {[attribute: string]: string} attrs key-value list of HTML attributes to add
       *
       * @returns {string} content wrapped in HTML element
       */
      wrap(tag, content, attrs = {}) {
        const htmlAttrs = Object.entries(attrs).map(([key, value]) => ` ${key}="${value}"`).join("");
        if (!content) {
          return `<${tag}${htmlAttrs}>`;
        }
        return `<${tag}${htmlAttrs}>${content}</${tag}>`;
      }
      /**
       * Writes text in the buffer to the summary buffer file and empties buffer. Will append by default.
       *
       * @param {SummaryWriteOptions} [options] (optional) options for write operation
       *
       * @returns {Promise<Summary>} summary instance
       */
      write(options) {
        return __awaiter(this, void 0, void 0, function* () {
          const overwrite = !!(options === null || options === void 0 ? void 0 : options.overwrite);
          const filePath = yield this.filePath();
          const writeFunc = overwrite ? writeFile : appendFile;
          yield writeFunc(filePath, this._buffer, { encoding: "utf8" });
          return this.emptyBuffer();
        });
      }
      /**
       * Clears the summary buffer and wipes the summary file
       *
       * @returns {Summary} summary instance
       */
      clear() {
        return __awaiter(this, void 0, void 0, function* () {
          return this.emptyBuffer().write({ overwrite: true });
        });
      }
      /**
       * Returns the current summary buffer as a string
       *
       * @returns {string} string of summary buffer
       */
      stringify() {
        return this._buffer;
      }
      /**
       * If the summary buffer is empty
       *
       * @returns {boolen} true if the buffer is empty
       */
      isEmptyBuffer() {
        return this._buffer.length === 0;
      }
      /**
       * Resets the summary buffer without writing to summary file
       *
       * @returns {Summary} summary instance
       */
      emptyBuffer() {
        this._buffer = "";
        return this;
      }
      /**
       * Adds raw text to the summary buffer
       *
       * @param {string} text content to add
       * @param {boolean} [addEOL=false] (optional) append an EOL to the raw text (default: false)
       *
       * @returns {Summary} summary instance
       */
      addRaw(text, addEOL = false) {
        this._buffer += text;
        return addEOL ? this.addEOL() : this;
      }
      /**
       * Adds the operating system-specific end-of-line marker to the buffer
       *
       * @returns {Summary} summary instance
       */
      addEOL() {
        return this.addRaw(os_1.EOL);
      }
      /**
       * Adds an HTML codeblock to the summary buffer
       *
       * @param {string} code content to render within fenced code block
       * @param {string} lang (optional) language to syntax highlight code
       *
       * @returns {Summary} summary instance
       */
      addCodeBlock(code, lang) {
        const attrs = Object.assign({}, lang && { lang });
        const element = this.wrap("pre", this.wrap("code", code), attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML list to the summary buffer
       *
       * @param {string[]} items list of items to render
       * @param {boolean} [ordered=false] (optional) if the rendered list should be ordered or not (default: false)
       *
       * @returns {Summary} summary instance
       */
      addList(items, ordered = false) {
        const tag = ordered ? "ol" : "ul";
        const listItems = items.map((item) => this.wrap("li", item)).join("");
        const element = this.wrap(tag, listItems);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML table to the summary buffer
       *
       * @param {SummaryTableCell[]} rows table rows
       *
       * @returns {Summary} summary instance
       */
      addTable(rows) {
        const tableBody = rows.map((row) => {
          const cells = row.map((cell) => {
            if (typeof cell === "string") {
              return this.wrap("td", cell);
            }
            const { header, data, colspan, rowspan } = cell;
            const tag = header ? "th" : "td";
            const attrs = Object.assign(Object.assign({}, colspan && { colspan }), rowspan && { rowspan });
            return this.wrap(tag, data, attrs);
          }).join("");
          return this.wrap("tr", cells);
        }).join("");
        const element = this.wrap("table", tableBody);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds a collapsable HTML details element to the summary buffer
       *
       * @param {string} label text for the closed state
       * @param {string} content collapsable content
       *
       * @returns {Summary} summary instance
       */
      addDetails(label, content) {
        const element = this.wrap("details", this.wrap("summary", label) + content);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML image tag to the summary buffer
       *
       * @param {string} src path to the image you to embed
       * @param {string} alt text description of the image
       * @param {SummaryImageOptions} options (optional) addition image attributes
       *
       * @returns {Summary} summary instance
       */
      addImage(src, alt, options) {
        const { width, height } = options || {};
        const attrs = Object.assign(Object.assign({}, width && { width }), height && { height });
        const element = this.wrap("img", null, Object.assign({ src, alt }, attrs));
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML section heading element
       *
       * @param {string} text heading text
       * @param {number | string} [level=1] (optional) the heading level, default: 1
       *
       * @returns {Summary} summary instance
       */
      addHeading(text, level) {
        const tag = `h${level}`;
        const allowedTag = ["h1", "h2", "h3", "h4", "h5", "h6"].includes(tag) ? tag : "h1";
        const element = this.wrap(allowedTag, text);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML thematic break (<hr>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addSeparator() {
        const element = this.wrap("hr", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML line break (<br>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addBreak() {
        const element = this.wrap("br", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML blockquote to the summary buffer
       *
       * @param {string} text quote text
       * @param {string} cite (optional) citation url
       *
       * @returns {Summary} summary instance
       */
      addQuote(text, cite) {
        const attrs = Object.assign({}, cite && { cite });
        const element = this.wrap("blockquote", text, attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML anchor tag to the summary buffer
       *
       * @param {string} text link text/content
       * @param {string} href hyperlink
       *
       * @returns {Summary} summary instance
       */
      addLink(text, href) {
        const element = this.wrap("a", text, { href });
        return this.addRaw(element).addEOL();
      }
    };
    var _summary = new Summary();
    exports2.markdownSummary = _summary;
    exports2.summary = _summary;
  }
});

// node_modules/@actions/core/lib/path-utils.js
var require_path_utils = __commonJS({
  "node_modules/@actions/core/lib/path-utils.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.toPlatformPath = exports2.toWin32Path = exports2.toPosixPath = void 0;
    var path2 = __importStar(require("path"));
    function toPosixPath(pth) {
      return pth.replace(/[\\]/g, "/");
    }
    exports2.toPosixPath = toPosixPath;
    function toWin32Path(pth) {
      return pth.replace(/[/]/g, "\\");
    }
    exports2.toWin32Path = toWin32Path;
    function toPlatformPath(pth) {
      return pth.replace(/[/\\]/g, path2.sep);
    }
    exports2.toPlatformPath = toPlatformPath;
  }
});

// node_modules/@actions/core/lib/core.js
var require_core = __commonJS({
  "node_modules/@actions/core/lib/core.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports2 && exports2.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports2 && exports2.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports2 && exports2.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve) {
          resolve(value);
        });
      }
      return new (P || (P = Promise))(function(resolve, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.getIDToken = exports2.getState = exports2.saveState = exports2.group = exports2.endGroup = exports2.startGroup = exports2.info = exports2.notice = exports2.warning = exports2.error = exports2.debug = exports2.isDebug = exports2.setFailed = exports2.setCommandEcho = exports2.setOutput = exports2.getBooleanInput = exports2.getMultilineInput = exports2.getInput = exports2.addPath = exports2.setSecret = exports2.exportVariable = exports2.ExitCode = void 0;
    var command_1 = require_command();
    var file_command_1 = require_file_command();
    var utils_1 = require_utils();
    var os = __importStar(require("os"));
    var path2 = __importStar(require("path"));
    var oidc_utils_1 = require_oidc_utils();
    var ExitCode;
    (function(ExitCode2) {
      ExitCode2[ExitCode2["Success"] = 0] = "Success";
      ExitCode2[ExitCode2["Failure"] = 1] = "Failure";
    })(ExitCode = exports2.ExitCode || (exports2.ExitCode = {}));
    function exportVariable(name, val) {
      const convertedVal = utils_1.toCommandValue(val);
      process.env[name] = convertedVal;
      const filePath = process.env["GITHUB_ENV"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("ENV", file_command_1.prepareKeyValueMessage(name, val));
      }
      command_1.issueCommand("set-env", { name }, convertedVal);
    }
    exports2.exportVariable = exportVariable;
    function setSecret(secret) {
      command_1.issueCommand("add-mask", {}, secret);
    }
    exports2.setSecret = setSecret;
    function addPath(inputPath) {
      const filePath = process.env["GITHUB_PATH"] || "";
      if (filePath) {
        file_command_1.issueFileCommand("PATH", inputPath);
      } else {
        command_1.issueCommand("add-path", {}, inputPath);
      }
      process.env["PATH"] = `${inputPath}${path2.delimiter}${process.env["PATH"]}`;
    }
    exports2.addPath = addPath;
    function getInput2(name, options) {
      const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "";
      if (options && options.required && !val) {
        throw new Error(`Input required and not supplied: ${name}`);
      }
      if (options && options.trimWhitespace === false) {
        return val;
      }
      return val.trim();
    }
    exports2.getInput = getInput2;
    function getMultilineInput(name, options) {
      const inputs = getInput2(name, options).split("\n").filter((x) => x !== "");
      if (options && options.trimWhitespace === false) {
        return inputs;
      }
      return inputs.map((input) => input.trim());
    }
    exports2.getMultilineInput = getMultilineInput;
    function getBooleanInput(name, options) {
      const trueValue = ["true", "True", "TRUE"];
      const falseValue = ["false", "False", "FALSE"];
      const val = getInput2(name, options);
      if (trueValue.includes(val))
        return true;
      if (falseValue.includes(val))
        return false;
      throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}
Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
    }
    exports2.getBooleanInput = getBooleanInput;
    function setOutput2(name, value) {
      const filePath = process.env["GITHUB_OUTPUT"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("OUTPUT", file_command_1.prepareKeyValueMessage(name, value));
      }
      process.stdout.write(os.EOL);
      command_1.issueCommand("set-output", { name }, utils_1.toCommandValue(value));
    }
    exports2.setOutput = setOutput2;
    function setCommandEcho(enabled) {
      command_1.issue("echo", enabled ? "on" : "off");
    }
    exports2.setCommandEcho = setCommandEcho;
    function setFailed2(message) {
      process.exitCode = ExitCode.Failure;
      error(message);
    }
    exports2.setFailed = setFailed2;
    function isDebug() {
      return process.env["RUNNER_DEBUG"] === "1";
    }
    exports2.isDebug = isDebug;
    function debug2(message) {
      command_1.issueCommand("debug", {}, message);
    }
    exports2.debug = debug2;
    function error(message, properties = {}) {
      command_1.issueCommand("error", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports2.error = error;
    function warning(message, properties = {}) {
      command_1.issueCommand("warning", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports2.warning = warning;
    function notice(message, properties = {}) {
      command_1.issueCommand("notice", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports2.notice = notice;
    function info(message) {
      process.stdout.write(message + os.EOL);
    }
    exports2.info = info;
    function startGroup(name) {
      command_1.issue("group", name);
    }
    exports2.startGroup = startGroup;
    function endGroup() {
      command_1.issue("endgroup");
    }
    exports2.endGroup = endGroup;
    function group(name, fn) {
      return __awaiter(this, void 0, void 0, function* () {
        startGroup(name);
        let result;
        try {
          result = yield fn();
        } finally {
          endGroup();
        }
        return result;
      });
    }
    exports2.group = group;
    function saveState(name, value) {
      const filePath = process.env["GITHUB_STATE"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("STATE", file_command_1.prepareKeyValueMessage(name, value));
      }
      command_1.issueCommand("save-state", { name }, utils_1.toCommandValue(value));
    }
    exports2.saveState = saveState;
    function getState(name) {
      return process.env[`STATE_${name}`] || "";
    }
    exports2.getState = getState;
    function getIDToken(aud) {
      return __awaiter(this, void 0, void 0, function* () {
        return yield oidc_utils_1.OidcClient.getIDToken(aud);
      });
    }
    exports2.getIDToken = getIDToken;
    var summary_1 = require_summary();
    Object.defineProperty(exports2, "summary", { enumerable: true, get: function() {
      return summary_1.summary;
    } });
    var summary_2 = require_summary();
    Object.defineProperty(exports2, "markdownSummary", { enumerable: true, get: function() {
      return summary_2.markdownSummary;
    } });
    var path_utils_1 = require_path_utils();
    Object.defineProperty(exports2, "toPosixPath", { enumerable: true, get: function() {
      return path_utils_1.toPosixPath;
    } });
    Object.defineProperty(exports2, "toWin32Path", { enumerable: true, get: function() {
      return path_utils_1.toWin32Path;
    } });
    Object.defineProperty(exports2, "toPlatformPath", { enumerable: true, get: function() {
      return path_utils_1.toPlatformPath;
    } });
  }
});

// node_modules/universal-user-agent/dist-node/index.js
var require_dist_node = __commonJS({
  "node_modules/universal-user-agent/dist-node/index.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    function getUserAgent() {
      if (typeof navigator === "object" && "userAgent" in navigator) {
        return navigator.userAgent;
      }
      if (typeof process === "object" && "version" in process) {
        return `Node.js/${process.version.substr(1)} (${process.platform}; ${process.arch})`;
      }
      return "<environment undetectable>";
    }
    exports2.getUserAgent = getUserAgent;
  }
});

// node_modules/before-after-hook/lib/register.js
var require_register = __commonJS({
  "node_modules/before-after-hook/lib/register.js"(exports2, module2) {
    module2.exports = register;
    function register(state, name, method, options) {
      if (typeof method !== "function") {
        throw new Error("method for before hook must be a function");
      }
      if (!options) {
        options = {};
      }
      if (Array.isArray(name)) {
        return name.reverse().reduce(function(callback, name2) {
          return register.bind(null, state, name2, callback, options);
        }, method)();
      }
      return Promise.resolve().then(function() {
        if (!state.registry[name]) {
          return method(options);
        }
        return state.registry[name].reduce(function(method2, registered) {
          return registered.hook.bind(null, method2, options);
        }, method)();
      });
    }
  }
});

// node_modules/before-after-hook/lib/add.js
var require_add = __commonJS({
  "node_modules/before-after-hook/lib/add.js"(exports2, module2) {
    module2.exports = addHook;
    function addHook(state, kind, name, hook) {
      var orig = hook;
      if (!state.registry[name]) {
        state.registry[name] = [];
      }
      if (kind === "before") {
        hook = function(method, options) {
          return Promise.resolve().then(orig.bind(null, options)).then(method.bind(null, options));
        };
      }
      if (kind === "after") {
        hook = function(method, options) {
          var result;
          return Promise.resolve().then(method.bind(null, options)).then(function(result_) {
            result = result_;
            return orig(result, options);
          }).then(function() {
            return result;
          });
        };
      }
      if (kind === "error") {
        hook = function(method, options) {
          return Promise.resolve().then(method.bind(null, options)).catch(function(error) {
            return orig(error, options);
          });
        };
      }
      state.registry[name].push({
        hook,
        orig
      });
    }
  }
});

// node_modules/before-after-hook/lib/remove.js
var require_remove = __commonJS({
  "node_modules/before-after-hook/lib/remove.js"(exports2, module2) {
    module2.exports = removeHook;
    function removeHook(state, name, method) {
      if (!state.registry[name]) {
        return;
      }
      var index = state.registry[name].map(function(registered) {
        return registered.orig;
      }).indexOf(method);
      if (index === -1) {
        return;
      }
      state.registry[name].splice(index, 1);
    }
  }
});

// node_modules/before-after-hook/index.js
var require_before_after_hook = __commonJS({
  "node_modules/before-after-hook/index.js"(exports2, module2) {
    var register = require_register();
    var addHook = require_add();
    var removeHook = require_remove();
    var bind = Function.bind;
    var bindable = bind.bind(bind);
    function bindApi(hook, state, name) {
      var removeHookRef = bindable(removeHook, null).apply(
        null,
        name ? [state, name] : [state]
      );
      hook.api = { remove: removeHookRef };
      hook.remove = removeHookRef;
      ["before", "error", "after", "wrap"].forEach(function(kind) {
        var args = name ? [state, kind, name] : [state, kind];
        hook[kind] = hook.api[kind] = bindable(addHook, null).apply(null, args);
      });
    }
    function HookSingular() {
      var singularHookName = "h";
      var singularHookState = {
        registry: {}
      };
      var singularHook = register.bind(null, singularHookState, singularHookName);
      bindApi(singularHook, singularHookState, singularHookName);
      return singularHook;
    }
    function HookCollection() {
      var state = {
        registry: {}
      };
      var hook = register.bind(null, state);
      bindApi(hook, state);
      return hook;
    }
    var collectionHookDeprecationMessageDisplayed = false;
    function Hook() {
      if (!collectionHookDeprecationMessageDisplayed) {
        console.warn(
          '[before-after-hook]: "Hook()" repurposing warning, use "Hook.Collection()". Read more: https://git.io/upgrade-before-after-hook-to-1.4'
        );
        collectionHookDeprecationMessageDisplayed = true;
      }
      return HookCollection();
    }
    Hook.Singular = HookSingular.bind();
    Hook.Collection = HookCollection.bind();
    module2.exports = Hook;
    module2.exports.Hook = Hook;
    module2.exports.Singular = Hook.Singular;
    module2.exports.Collection = Hook.Collection;
  }
});

// node_modules/is-plain-object/dist/is-plain-object.js
var require_is_plain_object = __commonJS({
  "node_modules/is-plain-object/dist/is-plain-object.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    function isObject(o) {
      return Object.prototype.toString.call(o) === "[object Object]";
    }
    function isPlainObject(o) {
      var ctor, prot;
      if (isObject(o) === false)
        return false;
      ctor = o.constructor;
      if (ctor === void 0)
        return true;
      prot = ctor.prototype;
      if (isObject(prot) === false)
        return false;
      if (prot.hasOwnProperty("isPrototypeOf") === false) {
        return false;
      }
      return true;
    }
    exports2.isPlainObject = isPlainObject;
  }
});

// node_modules/@octokit/endpoint/dist-node/index.js
var require_dist_node2 = __commonJS({
  "node_modules/@octokit/endpoint/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      endpoint: () => endpoint
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_universal_user_agent = require_dist_node();
    var VERSION = "9.0.0";
    var userAgent = `octokit-endpoint.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`;
    var DEFAULTS = {
      method: "GET",
      baseUrl: "https://api.github.com",
      headers: {
        accept: "application/vnd.github.v3+json",
        "user-agent": userAgent
      },
      mediaType: {
        format: ""
      }
    };
    function lowercaseKeys(object) {
      if (!object) {
        return {};
      }
      return Object.keys(object).reduce((newObj, key) => {
        newObj[key.toLowerCase()] = object[key];
        return newObj;
      }, {});
    }
    var import_is_plain_object = require_is_plain_object();
    function mergeDeep(defaults, options) {
      const result = Object.assign({}, defaults);
      Object.keys(options).forEach((key) => {
        if ((0, import_is_plain_object.isPlainObject)(options[key])) {
          if (!(key in defaults))
            Object.assign(result, { [key]: options[key] });
          else
            result[key] = mergeDeep(defaults[key], options[key]);
        } else {
          Object.assign(result, { [key]: options[key] });
        }
      });
      return result;
    }
    function removeUndefinedProperties(obj) {
      for (const key in obj) {
        if (obj[key] === void 0) {
          delete obj[key];
        }
      }
      return obj;
    }
    function merge(defaults, route, options) {
      if (typeof route === "string") {
        let [method, url] = route.split(" ");
        options = Object.assign(url ? { method, url } : { url: method }, options);
      } else {
        options = Object.assign({}, route);
      }
      options.headers = lowercaseKeys(options.headers);
      removeUndefinedProperties(options);
      removeUndefinedProperties(options.headers);
      const mergedOptions = mergeDeep(defaults || {}, options);
      if (options.url === "/graphql") {
        if (defaults && defaults.mediaType.previews?.length) {
          mergedOptions.mediaType.previews = defaults.mediaType.previews.filter(
            (preview) => !mergedOptions.mediaType.previews.includes(preview)
          ).concat(mergedOptions.mediaType.previews);
        }
        mergedOptions.mediaType.previews = (mergedOptions.mediaType.previews || []).map((preview) => preview.replace(/-preview/, ""));
      }
      return mergedOptions;
    }
    function addQueryParameters(url, parameters) {
      const separator = /\?/.test(url) ? "&" : "?";
      const names = Object.keys(parameters);
      if (names.length === 0) {
        return url;
      }
      return url + separator + names.map((name) => {
        if (name === "q") {
          return "q=" + parameters.q.split("+").map(encodeURIComponent).join("+");
        }
        return `${name}=${encodeURIComponent(parameters[name])}`;
      }).join("&");
    }
    var urlVariableRegex = /\{[^}]+\}/g;
    function removeNonChars(variableName) {
      return variableName.replace(/^\W+|\W+$/g, "").split(/,/);
    }
    function extractUrlVariableNames(url) {
      const matches = url.match(urlVariableRegex);
      if (!matches) {
        return [];
      }
      return matches.map(removeNonChars).reduce((a, b) => a.concat(b), []);
    }
    function omit(object, keysToOmit) {
      return Object.keys(object).filter((option) => !keysToOmit.includes(option)).reduce((obj, key) => {
        obj[key] = object[key];
        return obj;
      }, {});
    }
    function encodeReserved(str) {
      return str.split(/(%[0-9A-Fa-f]{2})/g).map(function(part) {
        if (!/%[0-9A-Fa-f]/.test(part)) {
          part = encodeURI(part).replace(/%5B/g, "[").replace(/%5D/g, "]");
        }
        return part;
      }).join("");
    }
    function encodeUnreserved(str) {
      return encodeURIComponent(str).replace(/[!'()*]/g, function(c) {
        return "%" + c.charCodeAt(0).toString(16).toUpperCase();
      });
    }
    function encodeValue(operator, value, key) {
      value = operator === "+" || operator === "#" ? encodeReserved(value) : encodeUnreserved(value);
      if (key) {
        return encodeUnreserved(key) + "=" + value;
      } else {
        return value;
      }
    }
    function isDefined(value) {
      return value !== void 0 && value !== null;
    }
    function isKeyOperator(operator) {
      return operator === ";" || operator === "&" || operator === "?";
    }
    function getValues(context, operator, key, modifier) {
      var value = context[key], result = [];
      if (isDefined(value) && value !== "") {
        if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
          value = value.toString();
          if (modifier && modifier !== "*") {
            value = value.substring(0, parseInt(modifier, 10));
          }
          result.push(
            encodeValue(operator, value, isKeyOperator(operator) ? key : "")
          );
        } else {
          if (modifier === "*") {
            if (Array.isArray(value)) {
              value.filter(isDefined).forEach(function(value2) {
                result.push(
                  encodeValue(operator, value2, isKeyOperator(operator) ? key : "")
                );
              });
            } else {
              Object.keys(value).forEach(function(k) {
                if (isDefined(value[k])) {
                  result.push(encodeValue(operator, value[k], k));
                }
              });
            }
          } else {
            const tmp = [];
            if (Array.isArray(value)) {
              value.filter(isDefined).forEach(function(value2) {
                tmp.push(encodeValue(operator, value2));
              });
            } else {
              Object.keys(value).forEach(function(k) {
                if (isDefined(value[k])) {
                  tmp.push(encodeUnreserved(k));
                  tmp.push(encodeValue(operator, value[k].toString()));
                }
              });
            }
            if (isKeyOperator(operator)) {
              result.push(encodeUnreserved(key) + "=" + tmp.join(","));
            } else if (tmp.length !== 0) {
              result.push(tmp.join(","));
            }
          }
        }
      } else {
        if (operator === ";") {
          if (isDefined(value)) {
            result.push(encodeUnreserved(key));
          }
        } else if (value === "" && (operator === "&" || operator === "?")) {
          result.push(encodeUnreserved(key) + "=");
        } else if (value === "") {
          result.push("");
        }
      }
      return result;
    }
    function parseUrl(template) {
      return {
        expand: expand.bind(null, template)
      };
    }
    function expand(template, context) {
      var operators = ["+", "#", ".", "/", ";", "?", "&"];
      return template.replace(
        /\{([^\{\}]+)\}|([^\{\}]+)/g,
        function(_, expression, literal) {
          if (expression) {
            let operator = "";
            const values = [];
            if (operators.indexOf(expression.charAt(0)) !== -1) {
              operator = expression.charAt(0);
              expression = expression.substr(1);
            }
            expression.split(/,/g).forEach(function(variable) {
              var tmp = /([^:\*]*)(?::(\d+)|(\*))?/.exec(variable);
              values.push(getValues(context, operator, tmp[1], tmp[2] || tmp[3]));
            });
            if (operator && operator !== "+") {
              var separator = ",";
              if (operator === "?") {
                separator = "&";
              } else if (operator !== "#") {
                separator = operator;
              }
              return (values.length !== 0 ? operator : "") + values.join(separator);
            } else {
              return values.join(",");
            }
          } else {
            return encodeReserved(literal);
          }
        }
      );
    }
    function parse2(options) {
      let method = options.method.toUpperCase();
      let url = (options.url || "/").replace(/:([a-z]\w+)/g, "{$1}");
      let headers = Object.assign({}, options.headers);
      let body;
      let parameters = omit(options, [
        "method",
        "baseUrl",
        "url",
        "headers",
        "request",
        "mediaType"
      ]);
      const urlVariableNames = extractUrlVariableNames(url);
      url = parseUrl(url).expand(parameters);
      if (!/^http/.test(url)) {
        url = options.baseUrl + url;
      }
      const omittedParameters = Object.keys(options).filter((option) => urlVariableNames.includes(option)).concat("baseUrl");
      const remainingParameters = omit(parameters, omittedParameters);
      const isBinaryRequest = /application\/octet-stream/i.test(headers.accept);
      if (!isBinaryRequest) {
        if (options.mediaType.format) {
          headers.accept = headers.accept.split(/,/).map(
            (format) => format.replace(
              /application\/vnd(\.\w+)(\.v3)?(\.\w+)?(\+json)?$/,
              `application/vnd$1$2.${options.mediaType.format}`
            )
          ).join(",");
        }
        if (url.endsWith("/graphql")) {
          if (options.mediaType.previews?.length) {
            const previewsFromAcceptHeader = headers.accept.match(/[\w-]+(?=-preview)/g) || [];
            headers.accept = previewsFromAcceptHeader.concat(options.mediaType.previews).map((preview) => {
              const format = options.mediaType.format ? `.${options.mediaType.format}` : "+json";
              return `application/vnd.github.${preview}-preview${format}`;
            }).join(",");
          }
        }
      }
      if (["GET", "HEAD"].includes(method)) {
        url = addQueryParameters(url, remainingParameters);
      } else {
        if ("data" in remainingParameters) {
          body = remainingParameters.data;
        } else {
          if (Object.keys(remainingParameters).length) {
            body = remainingParameters;
          }
        }
      }
      if (!headers["content-type"] && typeof body !== "undefined") {
        headers["content-type"] = "application/json; charset=utf-8";
      }
      if (["PATCH", "PUT"].includes(method) && typeof body === "undefined") {
        body = "";
      }
      return Object.assign(
        { method, url, headers },
        typeof body !== "undefined" ? { body } : null,
        options.request ? { request: options.request } : null
      );
    }
    function endpointWithDefaults(defaults, route, options) {
      return parse2(merge(defaults, route, options));
    }
    function withDefaults(oldDefaults, newDefaults) {
      const DEFAULTS2 = merge(oldDefaults, newDefaults);
      const endpoint2 = endpointWithDefaults.bind(null, DEFAULTS2);
      return Object.assign(endpoint2, {
        DEFAULTS: DEFAULTS2,
        defaults: withDefaults.bind(null, DEFAULTS2),
        merge: merge.bind(null, DEFAULTS2),
        parse: parse2
      });
    }
    var endpoint = withDefaults(null, DEFAULTS);
  }
});

// node_modules/deprecation/dist-node/index.js
var require_dist_node3 = __commonJS({
  "node_modules/deprecation/dist-node/index.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    var Deprecation = class extends Error {
      constructor(message) {
        super(message);
        if (Error.captureStackTrace) {
          Error.captureStackTrace(this, this.constructor);
        }
        this.name = "Deprecation";
      }
    };
    exports2.Deprecation = Deprecation;
  }
});

// node_modules/wrappy/wrappy.js
var require_wrappy = __commonJS({
  "node_modules/wrappy/wrappy.js"(exports2, module2) {
    module2.exports = wrappy;
    function wrappy(fn, cb) {
      if (fn && cb)
        return wrappy(fn)(cb);
      if (typeof fn !== "function")
        throw new TypeError("need wrapper function");
      Object.keys(fn).forEach(function(k) {
        wrapper[k] = fn[k];
      });
      return wrapper;
      function wrapper() {
        var args = new Array(arguments.length);
        for (var i = 0; i < args.length; i++) {
          args[i] = arguments[i];
        }
        var ret = fn.apply(this, args);
        var cb2 = args[args.length - 1];
        if (typeof ret === "function" && ret !== cb2) {
          Object.keys(cb2).forEach(function(k) {
            ret[k] = cb2[k];
          });
        }
        return ret;
      }
    }
  }
});

// node_modules/once/once.js
var require_once = __commonJS({
  "node_modules/once/once.js"(exports2, module2) {
    var wrappy = require_wrappy();
    module2.exports = wrappy(once);
    module2.exports.strict = wrappy(onceStrict);
    once.proto = once(function() {
      Object.defineProperty(Function.prototype, "once", {
        value: function() {
          return once(this);
        },
        configurable: true
      });
      Object.defineProperty(Function.prototype, "onceStrict", {
        value: function() {
          return onceStrict(this);
        },
        configurable: true
      });
    });
    function once(fn) {
      var f = function() {
        if (f.called)
          return f.value;
        f.called = true;
        return f.value = fn.apply(this, arguments);
      };
      f.called = false;
      return f;
    }
    function onceStrict(fn) {
      var f = function() {
        if (f.called)
          throw new Error(f.onceError);
        f.called = true;
        return f.value = fn.apply(this, arguments);
      };
      var name = fn.name || "Function wrapped with `once`";
      f.onceError = name + " shouldn't be called more than once";
      f.called = false;
      return f;
    }
  }
});

// node_modules/@octokit/request-error/dist-node/index.js
var require_dist_node4 = __commonJS({
  "node_modules/@octokit/request-error/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __create2 = Object.create;
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __getProtoOf2 = Object.getPrototypeOf;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toESM2 = (mod, isNodeMode, target) => (target = mod != null ? __create2(__getProtoOf2(mod)) : {}, __copyProps2(
      // If the importer is in node compatibility mode or this is not an ESM
      // file that has been converted to a CommonJS file using a Babel-
      // compatible transform (i.e. "__esModule" has not been set), then set
      // "default" to the CommonJS "module.exports" for node compatibility.
      isNodeMode || !mod || !mod.__esModule ? __defProp2(target, "default", { value: mod, enumerable: true }) : target,
      mod
    ));
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      RequestError: () => RequestError2
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_deprecation = require_dist_node3();
    var import_once = __toESM2(require_once());
    var logOnceCode = (0, import_once.default)((deprecation) => console.warn(deprecation));
    var logOnceHeaders = (0, import_once.default)((deprecation) => console.warn(deprecation));
    var RequestError2 = class extends Error {
      constructor(message, statusCode, options) {
        super(message);
        if (Error.captureStackTrace) {
          Error.captureStackTrace(this, this.constructor);
        }
        this.name = "HttpError";
        this.status = statusCode;
        let headers;
        if ("headers" in options && typeof options.headers !== "undefined") {
          headers = options.headers;
        }
        if ("response" in options) {
          this.response = options.response;
          headers = options.response.headers;
        }
        const requestCopy = Object.assign({}, options.request);
        if (options.request.headers.authorization) {
          requestCopy.headers = Object.assign({}, options.request.headers, {
            authorization: options.request.headers.authorization.replace(
              / .*$/,
              " [REDACTED]"
            )
          });
        }
        requestCopy.url = requestCopy.url.replace(/\bclient_secret=\w+/g, "client_secret=[REDACTED]").replace(/\baccess_token=\w+/g, "access_token=[REDACTED]");
        this.request = requestCopy;
        Object.defineProperty(this, "code", {
          get() {
            logOnceCode(
              new import_deprecation.Deprecation(
                "[@octokit/request-error] `error.code` is deprecated, use `error.status`."
              )
            );
            return statusCode;
          }
        });
        Object.defineProperty(this, "headers", {
          get() {
            logOnceHeaders(
              new import_deprecation.Deprecation(
                "[@octokit/request-error] `error.headers` is deprecated, use `error.response.headers`."
              )
            );
            return headers || {};
          }
        });
      }
    };
  }
});

// node_modules/@octokit/request/dist-node/index.js
var require_dist_node5 = __commonJS({
  "node_modules/@octokit/request/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      request: () => request
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_endpoint = require_dist_node2();
    var import_universal_user_agent = require_dist_node();
    var VERSION = "8.1.1";
    var import_is_plain_object = require_is_plain_object();
    var import_request_error = require_dist_node4();
    function getBufferResponse(response) {
      return response.arrayBuffer();
    }
    function fetchWrapper(requestOptions) {
      var _a, _b, _c;
      const log = requestOptions.request && requestOptions.request.log ? requestOptions.request.log : console;
      const parseSuccessResponseBody = ((_a = requestOptions.request) == null ? void 0 : _a.parseSuccessResponseBody) !== false;
      if ((0, import_is_plain_object.isPlainObject)(requestOptions.body) || Array.isArray(requestOptions.body)) {
        requestOptions.body = JSON.stringify(requestOptions.body);
      }
      let headers = {};
      let status;
      let url;
      let { fetch } = globalThis;
      if ((_b = requestOptions.request) == null ? void 0 : _b.fetch) {
        fetch = requestOptions.request.fetch;
      }
      if (!fetch) {
        throw new Error(
          "fetch is not set. Please pass a fetch implementation as new Octokit({ request: { fetch }}). Learn more at https://github.com/octokit/octokit.js/#fetch-missing"
        );
      }
      return fetch(requestOptions.url, {
        method: requestOptions.method,
        body: requestOptions.body,
        headers: requestOptions.headers,
        signal: (_c = requestOptions.request) == null ? void 0 : _c.signal,
        // duplex must be set if request.body is ReadableStream or Async Iterables.
        // See https://fetch.spec.whatwg.org/#dom-requestinit-duplex.
        ...requestOptions.body && { duplex: "half" }
      }).then(async (response) => {
        url = response.url;
        status = response.status;
        for (const keyAndValue of response.headers) {
          headers[keyAndValue[0]] = keyAndValue[1];
        }
        if ("deprecation" in headers) {
          const matches = headers.link && headers.link.match(/<([^>]+)>; rel="deprecation"/);
          const deprecationLink = matches && matches.pop();
          log.warn(
            `[@octokit/request] "${requestOptions.method} ${requestOptions.url}" is deprecated. It is scheduled to be removed on ${headers.sunset}${deprecationLink ? `. See ${deprecationLink}` : ""}`
          );
        }
        if (status === 204 || status === 205) {
          return;
        }
        if (requestOptions.method === "HEAD") {
          if (status < 400) {
            return;
          }
          throw new import_request_error.RequestError(response.statusText, status, {
            response: {
              url,
              status,
              headers,
              data: void 0
            },
            request: requestOptions
          });
        }
        if (status === 304) {
          throw new import_request_error.RequestError("Not modified", status, {
            response: {
              url,
              status,
              headers,
              data: await getResponseData(response)
            },
            request: requestOptions
          });
        }
        if (status >= 400) {
          const data = await getResponseData(response);
          const error = new import_request_error.RequestError(toErrorMessage(data), status, {
            response: {
              url,
              status,
              headers,
              data
            },
            request: requestOptions
          });
          throw error;
        }
        return parseSuccessResponseBody ? await getResponseData(response) : response.body;
      }).then((data) => {
        return {
          status,
          url,
          headers,
          data
        };
      }).catch((error) => {
        if (error instanceof import_request_error.RequestError)
          throw error;
        else if (error.name === "AbortError")
          throw error;
        throw new import_request_error.RequestError(error.message, 500, {
          request: requestOptions
        });
      });
    }
    async function getResponseData(response) {
      const contentType = response.headers.get("content-type");
      if (/application\/json/.test(contentType)) {
        return response.json();
      }
      if (!contentType || /^text\/|charset=utf-8$/.test(contentType)) {
        return response.text();
      }
      return getBufferResponse(response);
    }
    function toErrorMessage(data) {
      if (typeof data === "string")
        return data;
      if ("message" in data) {
        if (Array.isArray(data.errors)) {
          return `${data.message}: ${data.errors.map(JSON.stringify).join(", ")}`;
        }
        return data.message;
      }
      return `Unknown error: ${JSON.stringify(data)}`;
    }
    function withDefaults(oldEndpoint, newDefaults) {
      const endpoint2 = oldEndpoint.defaults(newDefaults);
      const newApi = function(route, parameters) {
        const endpointOptions = endpoint2.merge(route, parameters);
        if (!endpointOptions.request || !endpointOptions.request.hook) {
          return fetchWrapper(endpoint2.parse(endpointOptions));
        }
        const request2 = (route2, parameters2) => {
          return fetchWrapper(
            endpoint2.parse(endpoint2.merge(route2, parameters2))
          );
        };
        Object.assign(request2, {
          endpoint: endpoint2,
          defaults: withDefaults.bind(null, endpoint2)
        });
        return endpointOptions.request.hook(request2, endpointOptions);
      };
      return Object.assign(newApi, {
        endpoint: endpoint2,
        defaults: withDefaults.bind(null, endpoint2)
      });
    }
    var request = withDefaults(import_endpoint.endpoint, {
      headers: {
        "user-agent": `octokit-request.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`
      }
    });
  }
});

// node_modules/@octokit/graphql/dist-node/index.js
var require_dist_node6 = __commonJS({
  "node_modules/@octokit/graphql/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      GraphqlResponseError: () => GraphqlResponseError,
      graphql: () => graphql2,
      withCustomRequest: () => withCustomRequest
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_request3 = require_dist_node5();
    var import_universal_user_agent = require_dist_node();
    var VERSION = "7.0.1";
    var import_request2 = require_dist_node5();
    var import_request = require_dist_node5();
    function _buildMessageForResponseErrors(data) {
      return `Request failed due to following response errors:
` + data.errors.map((e) => ` - ${e.message}`).join("\n");
    }
    var GraphqlResponseError = class extends Error {
      constructor(request2, headers, response) {
        super(_buildMessageForResponseErrors(response));
        this.request = request2;
        this.headers = headers;
        this.response = response;
        this.name = "GraphqlResponseError";
        this.errors = response.errors;
        this.data = response.data;
        if (Error.captureStackTrace) {
          Error.captureStackTrace(this, this.constructor);
        }
      }
    };
    var NON_VARIABLE_OPTIONS = [
      "method",
      "baseUrl",
      "url",
      "headers",
      "request",
      "query",
      "mediaType"
    ];
    var FORBIDDEN_VARIABLE_OPTIONS = ["query", "method", "url"];
    var GHES_V3_SUFFIX_REGEX = /\/api\/v3\/?$/;
    function graphql(request2, query, options) {
      if (options) {
        if (typeof query === "string" && "query" in options) {
          return Promise.reject(
            new Error(`[@octokit/graphql] "query" cannot be used as variable name`)
          );
        }
        for (const key in options) {
          if (!FORBIDDEN_VARIABLE_OPTIONS.includes(key))
            continue;
          return Promise.reject(
            new Error(
              `[@octokit/graphql] "${key}" cannot be used as variable name`
            )
          );
        }
      }
      const parsedOptions = typeof query === "string" ? Object.assign({ query }, options) : query;
      const requestOptions = Object.keys(
        parsedOptions
      ).reduce((result, key) => {
        if (NON_VARIABLE_OPTIONS.includes(key)) {
          result[key] = parsedOptions[key];
          return result;
        }
        if (!result.variables) {
          result.variables = {};
        }
        result.variables[key] = parsedOptions[key];
        return result;
      }, {});
      const baseUrl = parsedOptions.baseUrl || request2.endpoint.DEFAULTS.baseUrl;
      if (GHES_V3_SUFFIX_REGEX.test(baseUrl)) {
        requestOptions.url = baseUrl.replace(GHES_V3_SUFFIX_REGEX, "/api/graphql");
      }
      return request2(requestOptions).then((response) => {
        if (response.data.errors) {
          const headers = {};
          for (const key of Object.keys(response.headers)) {
            headers[key] = response.headers[key];
          }
          throw new GraphqlResponseError(
            requestOptions,
            headers,
            response.data
          );
        }
        return response.data.data;
      });
    }
    function withDefaults(request2, newDefaults) {
      const newRequest = request2.defaults(newDefaults);
      const newApi = (query, options) => {
        return graphql(newRequest, query, options);
      };
      return Object.assign(newApi, {
        defaults: withDefaults.bind(null, newRequest),
        endpoint: newRequest.endpoint
      });
    }
    var graphql2 = withDefaults(import_request3.request, {
      headers: {
        "user-agent": `octokit-graphql.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`
      },
      method: "POST",
      url: "/graphql"
    });
    function withCustomRequest(customRequest) {
      return withDefaults(customRequest, {
        method: "POST",
        url: "/graphql"
      });
    }
  }
});

// node_modules/@octokit/auth-token/dist-node/index.js
var require_dist_node7 = __commonJS({
  "node_modules/@octokit/auth-token/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      createTokenAuth: () => createTokenAuth
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var REGEX_IS_INSTALLATION_LEGACY = /^v1\./;
    var REGEX_IS_INSTALLATION = /^ghs_/;
    var REGEX_IS_USER_TO_SERVER = /^ghu_/;
    async function auth(token) {
      const isApp = token.split(/\./).length === 3;
      const isInstallation = REGEX_IS_INSTALLATION_LEGACY.test(token) || REGEX_IS_INSTALLATION.test(token);
      const isUserToServer = REGEX_IS_USER_TO_SERVER.test(token);
      const tokenType = isApp ? "app" : isInstallation ? "installation" : isUserToServer ? "user-to-server" : "oauth";
      return {
        type: "token",
        token,
        tokenType
      };
    }
    function withAuthorizationPrefix(token) {
      if (token.split(/\./).length === 3) {
        return `bearer ${token}`;
      }
      return `token ${token}`;
    }
    async function hook(token, request, route, parameters) {
      const endpoint = request.endpoint.merge(
        route,
        parameters
      );
      endpoint.headers.authorization = withAuthorizationPrefix(token);
      return request(endpoint);
    }
    var createTokenAuth = function createTokenAuth2(token) {
      if (!token) {
        throw new Error("[@octokit/auth-token] No token passed to createTokenAuth");
      }
      if (typeof token !== "string") {
        throw new Error(
          "[@octokit/auth-token] Token passed to createTokenAuth is not a string"
        );
      }
      token = token.replace(/^(token|bearer) +/i, "");
      return Object.assign(auth.bind(null, token), {
        hook: hook.bind(null, token)
      });
    };
  }
});

// node_modules/@octokit/core/dist-node/index.js
var require_dist_node8 = __commonJS({
  "node_modules/@octokit/core/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      Octokit: () => Octokit2
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_universal_user_agent = require_dist_node();
    var import_before_after_hook = require_before_after_hook();
    var import_request = require_dist_node5();
    var import_graphql = require_dist_node6();
    var import_auth_token = require_dist_node7();
    var VERSION = "5.0.0";
    var Octokit2 = class {
      static {
        this.VERSION = VERSION;
      }
      static defaults(defaults) {
        const OctokitWithDefaults = class extends this {
          constructor(...args) {
            const options = args[0] || {};
            if (typeof defaults === "function") {
              super(defaults(options));
              return;
            }
            super(
              Object.assign(
                {},
                defaults,
                options,
                options.userAgent && defaults.userAgent ? {
                  userAgent: `${options.userAgent} ${defaults.userAgent}`
                } : null
              )
            );
          }
        };
        return OctokitWithDefaults;
      }
      static {
        this.plugins = [];
      }
      /**
       * Attach a plugin (or many) to your Octokit instance.
       *
       * @example
       * const API = Octokit.plugin(plugin1, plugin2, plugin3, ...)
       */
      static plugin(...newPlugins) {
        const currentPlugins = this.plugins;
        const NewOctokit = class extends this {
          static {
            this.plugins = currentPlugins.concat(
              newPlugins.filter((plugin) => !currentPlugins.includes(plugin))
            );
          }
        };
        return NewOctokit;
      }
      constructor(options = {}) {
        const hook = new import_before_after_hook.Collection();
        const requestDefaults = {
          baseUrl: import_request.request.endpoint.DEFAULTS.baseUrl,
          headers: {},
          request: Object.assign({}, options.request, {
            // @ts-ignore internal usage only, no need to type
            hook: hook.bind(null, "request")
          }),
          mediaType: {
            previews: [],
            format: ""
          }
        };
        requestDefaults.headers["user-agent"] = [
          options.userAgent,
          `octokit-core.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`
        ].filter(Boolean).join(" ");
        if (options.baseUrl) {
          requestDefaults.baseUrl = options.baseUrl;
        }
        if (options.previews) {
          requestDefaults.mediaType.previews = options.previews;
        }
        if (options.timeZone) {
          requestDefaults.headers["time-zone"] = options.timeZone;
        }
        this.request = import_request.request.defaults(requestDefaults);
        this.graphql = (0, import_graphql.withCustomRequest)(this.request).defaults(requestDefaults);
        this.log = Object.assign(
          {
            debug: () => {
            },
            info: () => {
            },
            warn: console.warn.bind(console),
            error: console.error.bind(console)
          },
          options.log
        );
        this.hook = hook;
        if (!options.authStrategy) {
          if (!options.auth) {
            this.auth = async () => ({
              type: "unauthenticated"
            });
          } else {
            const auth = (0, import_auth_token.createTokenAuth)(options.auth);
            hook.wrap("request", auth.hook);
            this.auth = auth;
          }
        } else {
          const { authStrategy, ...otherOptions } = options;
          const auth = authStrategy(
            Object.assign(
              {
                request: this.request,
                log: this.log,
                // we pass the current octokit instance as well as its constructor options
                // to allow for authentication strategies that return a new octokit instance
                // that shares the same internal state as the current one. The original
                // requirement for this was the "event-octokit" authentication strategy
                // of https://github.com/probot/octokit-auth-probot.
                octokit: this,
                octokitOptions: otherOptions
              },
              options.auth
            )
          );
          hook.wrap("request", auth.hook);
          this.auth = auth;
        }
        const classConstructor = this.constructor;
        classConstructor.plugins.forEach((plugin) => {
          Object.assign(this, plugin(this, options));
        });
      }
    };
  }
});

// node_modules/@octokit/plugin-paginate-rest/dist-node/index.js
var require_dist_node9 = __commonJS({
  "node_modules/@octokit/plugin-paginate-rest/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      composePaginateRest: () => composePaginateRest,
      isPaginatingEndpoint: () => isPaginatingEndpoint,
      paginateRest: () => paginateRest,
      paginatingEndpoints: () => paginatingEndpoints
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var VERSION = "9.1.4";
    function normalizePaginatedListResponse(response) {
      if (!response.data) {
        return {
          ...response,
          data: []
        };
      }
      const responseNeedsNormalization = "total_count" in response.data && !("url" in response.data);
      if (!responseNeedsNormalization)
        return response;
      const incompleteResults = response.data.incomplete_results;
      const repositorySelection = response.data.repository_selection;
      const totalCount = response.data.total_count;
      delete response.data.incomplete_results;
      delete response.data.repository_selection;
      delete response.data.total_count;
      const namespaceKey = Object.keys(response.data)[0];
      const data = response.data[namespaceKey];
      response.data = data;
      if (typeof incompleteResults !== "undefined") {
        response.data.incomplete_results = incompleteResults;
      }
      if (typeof repositorySelection !== "undefined") {
        response.data.repository_selection = repositorySelection;
      }
      response.data.total_count = totalCount;
      return response;
    }
    function iterator(octokit, route, parameters) {
      const options = typeof route === "function" ? route.endpoint(parameters) : octokit.request.endpoint(route, parameters);
      const requestMethod = typeof route === "function" ? route : octokit.request;
      const method = options.method;
      const headers = options.headers;
      let url = options.url;
      return {
        [Symbol.asyncIterator]: () => ({
          async next() {
            if (!url)
              return { done: true };
            try {
              const response = await requestMethod({ method, url, headers });
              const normalizedResponse = normalizePaginatedListResponse(response);
              url = ((normalizedResponse.headers.link || "").match(
                /<([^>]+)>;\s*rel="next"/
              ) || [])[1];
              return { value: normalizedResponse };
            } catch (error) {
              if (error.status !== 409)
                throw error;
              url = "";
              return {
                value: {
                  status: 200,
                  headers: {},
                  data: []
                }
              };
            }
          }
        })
      };
    }
    function paginate(octokit, route, parameters, mapFn) {
      if (typeof parameters === "function") {
        mapFn = parameters;
        parameters = void 0;
      }
      return gather(
        octokit,
        [],
        iterator(octokit, route, parameters)[Symbol.asyncIterator](),
        mapFn
      );
    }
    function gather(octokit, results, iterator2, mapFn) {
      return iterator2.next().then((result) => {
        if (result.done) {
          return results;
        }
        let earlyExit = false;
        function done() {
          earlyExit = true;
        }
        results = results.concat(
          mapFn ? mapFn(result.value, done) : result.value.data
        );
        if (earlyExit) {
          return results;
        }
        return gather(octokit, results, iterator2, mapFn);
      });
    }
    var composePaginateRest = Object.assign(paginate, {
      iterator
    });
    var paginatingEndpoints = [
      "GET /advisories",
      "GET /app/hook/deliveries",
      "GET /app/installation-requests",
      "GET /app/installations",
      "GET /assignments/{assignment_id}/accepted_assignments",
      "GET /classrooms",
      "GET /classrooms/{classroom_id}/assignments",
      "GET /enterprises/{enterprise}/dependabot/alerts",
      "GET /enterprises/{enterprise}/secret-scanning/alerts",
      "GET /events",
      "GET /gists",
      "GET /gists/public",
      "GET /gists/starred",
      "GET /gists/{gist_id}/comments",
      "GET /gists/{gist_id}/commits",
      "GET /gists/{gist_id}/forks",
      "GET /installation/repositories",
      "GET /issues",
      "GET /licenses",
      "GET /marketplace_listing/plans",
      "GET /marketplace_listing/plans/{plan_id}/accounts",
      "GET /marketplace_listing/stubbed/plans",
      "GET /marketplace_listing/stubbed/plans/{plan_id}/accounts",
      "GET /networks/{owner}/{repo}/events",
      "GET /notifications",
      "GET /organizations",
      "GET /orgs/{org}/actions/cache/usage-by-repository",
      "GET /orgs/{org}/actions/permissions/repositories",
      "GET /orgs/{org}/actions/runners",
      "GET /orgs/{org}/actions/secrets",
      "GET /orgs/{org}/actions/secrets/{secret_name}/repositories",
      "GET /orgs/{org}/actions/variables",
      "GET /orgs/{org}/actions/variables/{name}/repositories",
      "GET /orgs/{org}/blocks",
      "GET /orgs/{org}/code-scanning/alerts",
      "GET /orgs/{org}/codespaces",
      "GET /orgs/{org}/codespaces/secrets",
      "GET /orgs/{org}/codespaces/secrets/{secret_name}/repositories",
      "GET /orgs/{org}/copilot/billing/seats",
      "GET /orgs/{org}/dependabot/alerts",
      "GET /orgs/{org}/dependabot/secrets",
      "GET /orgs/{org}/dependabot/secrets/{secret_name}/repositories",
      "GET /orgs/{org}/events",
      "GET /orgs/{org}/failed_invitations",
      "GET /orgs/{org}/hooks",
      "GET /orgs/{org}/hooks/{hook_id}/deliveries",
      "GET /orgs/{org}/installations",
      "GET /orgs/{org}/invitations",
      "GET /orgs/{org}/invitations/{invitation_id}/teams",
      "GET /orgs/{org}/issues",
      "GET /orgs/{org}/members",
      "GET /orgs/{org}/members/{username}/codespaces",
      "GET /orgs/{org}/migrations",
      "GET /orgs/{org}/migrations/{migration_id}/repositories",
      "GET /orgs/{org}/outside_collaborators",
      "GET /orgs/{org}/packages",
      "GET /orgs/{org}/packages/{package_type}/{package_name}/versions",
      "GET /orgs/{org}/personal-access-token-requests",
      "GET /orgs/{org}/personal-access-token-requests/{pat_request_id}/repositories",
      "GET /orgs/{org}/personal-access-tokens",
      "GET /orgs/{org}/personal-access-tokens/{pat_id}/repositories",
      "GET /orgs/{org}/projects",
      "GET /orgs/{org}/properties/values",
      "GET /orgs/{org}/public_members",
      "GET /orgs/{org}/repos",
      "GET /orgs/{org}/rulesets",
      "GET /orgs/{org}/rulesets/rule-suites",
      "GET /orgs/{org}/secret-scanning/alerts",
      "GET /orgs/{org}/security-advisories",
      "GET /orgs/{org}/teams",
      "GET /orgs/{org}/teams/{team_slug}/discussions",
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments",
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions",
      "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions",
      "GET /orgs/{org}/teams/{team_slug}/invitations",
      "GET /orgs/{org}/teams/{team_slug}/members",
      "GET /orgs/{org}/teams/{team_slug}/projects",
      "GET /orgs/{org}/teams/{team_slug}/repos",
      "GET /orgs/{org}/teams/{team_slug}/teams",
      "GET /projects/columns/{column_id}/cards",
      "GET /projects/{project_id}/collaborators",
      "GET /projects/{project_id}/columns",
      "GET /repos/{owner}/{repo}/actions/artifacts",
      "GET /repos/{owner}/{repo}/actions/caches",
      "GET /repos/{owner}/{repo}/actions/organization-secrets",
      "GET /repos/{owner}/{repo}/actions/organization-variables",
      "GET /repos/{owner}/{repo}/actions/runners",
      "GET /repos/{owner}/{repo}/actions/runs",
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts",
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs",
      "GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs",
      "GET /repos/{owner}/{repo}/actions/secrets",
      "GET /repos/{owner}/{repo}/actions/variables",
      "GET /repos/{owner}/{repo}/actions/workflows",
      "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs",
      "GET /repos/{owner}/{repo}/activity",
      "GET /repos/{owner}/{repo}/assignees",
      "GET /repos/{owner}/{repo}/branches",
      "GET /repos/{owner}/{repo}/check-runs/{check_run_id}/annotations",
      "GET /repos/{owner}/{repo}/check-suites/{check_suite_id}/check-runs",
      "GET /repos/{owner}/{repo}/code-scanning/alerts",
      "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
      "GET /repos/{owner}/{repo}/code-scanning/analyses",
      "GET /repos/{owner}/{repo}/codespaces",
      "GET /repos/{owner}/{repo}/codespaces/devcontainers",
      "GET /repos/{owner}/{repo}/codespaces/secrets",
      "GET /repos/{owner}/{repo}/collaborators",
      "GET /repos/{owner}/{repo}/comments",
      "GET /repos/{owner}/{repo}/comments/{comment_id}/reactions",
      "GET /repos/{owner}/{repo}/commits",
      "GET /repos/{owner}/{repo}/commits/{commit_sha}/comments",
      "GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls",
      "GET /repos/{owner}/{repo}/commits/{ref}/check-runs",
      "GET /repos/{owner}/{repo}/commits/{ref}/check-suites",
      "GET /repos/{owner}/{repo}/commits/{ref}/status",
      "GET /repos/{owner}/{repo}/commits/{ref}/statuses",
      "GET /repos/{owner}/{repo}/contributors",
      "GET /repos/{owner}/{repo}/dependabot/alerts",
      "GET /repos/{owner}/{repo}/dependabot/secrets",
      "GET /repos/{owner}/{repo}/deployments",
      "GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses",
      "GET /repos/{owner}/{repo}/environments",
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies",
      "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/apps",
      "GET /repos/{owner}/{repo}/events",
      "GET /repos/{owner}/{repo}/forks",
      "GET /repos/{owner}/{repo}/hooks",
      "GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries",
      "GET /repos/{owner}/{repo}/invitations",
      "GET /repos/{owner}/{repo}/issues",
      "GET /repos/{owner}/{repo}/issues/comments",
      "GET /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions",
      "GET /repos/{owner}/{repo}/issues/events",
      "GET /repos/{owner}/{repo}/issues/{issue_number}/comments",
      "GET /repos/{owner}/{repo}/issues/{issue_number}/events",
      "GET /repos/{owner}/{repo}/issues/{issue_number}/labels",
      "GET /repos/{owner}/{repo}/issues/{issue_number}/reactions",
      "GET /repos/{owner}/{repo}/issues/{issue_number}/timeline",
      "GET /repos/{owner}/{repo}/keys",
      "GET /repos/{owner}/{repo}/labels",
      "GET /repos/{owner}/{repo}/milestones",
      "GET /repos/{owner}/{repo}/milestones/{milestone_number}/labels",
      "GET /repos/{owner}/{repo}/notifications",
      "GET /repos/{owner}/{repo}/pages/builds",
      "GET /repos/{owner}/{repo}/projects",
      "GET /repos/{owner}/{repo}/pulls",
      "GET /repos/{owner}/{repo}/pulls/comments",
      "GET /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions",
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/comments",
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/commits",
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/files",
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews",
      "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/comments",
      "GET /repos/{owner}/{repo}/releases",
      "GET /repos/{owner}/{repo}/releases/{release_id}/assets",
      "GET /repos/{owner}/{repo}/releases/{release_id}/reactions",
      "GET /repos/{owner}/{repo}/rules/branches/{branch}",
      "GET /repos/{owner}/{repo}/rulesets",
      "GET /repos/{owner}/{repo}/rulesets/rule-suites",
      "GET /repos/{owner}/{repo}/secret-scanning/alerts",
      "GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations",
      "GET /repos/{owner}/{repo}/security-advisories",
      "GET /repos/{owner}/{repo}/stargazers",
      "GET /repos/{owner}/{repo}/subscribers",
      "GET /repos/{owner}/{repo}/tags",
      "GET /repos/{owner}/{repo}/teams",
      "GET /repos/{owner}/{repo}/topics",
      "GET /repositories",
      "GET /repositories/{repository_id}/environments/{environment_name}/secrets",
      "GET /repositories/{repository_id}/environments/{environment_name}/variables",
      "GET /search/code",
      "GET /search/commits",
      "GET /search/issues",
      "GET /search/labels",
      "GET /search/repositories",
      "GET /search/topics",
      "GET /search/users",
      "GET /teams/{team_id}/discussions",
      "GET /teams/{team_id}/discussions/{discussion_number}/comments",
      "GET /teams/{team_id}/discussions/{discussion_number}/comments/{comment_number}/reactions",
      "GET /teams/{team_id}/discussions/{discussion_number}/reactions",
      "GET /teams/{team_id}/invitations",
      "GET /teams/{team_id}/members",
      "GET /teams/{team_id}/projects",
      "GET /teams/{team_id}/repos",
      "GET /teams/{team_id}/teams",
      "GET /user/blocks",
      "GET /user/codespaces",
      "GET /user/codespaces/secrets",
      "GET /user/emails",
      "GET /user/followers",
      "GET /user/following",
      "GET /user/gpg_keys",
      "GET /user/installations",
      "GET /user/installations/{installation_id}/repositories",
      "GET /user/issues",
      "GET /user/keys",
      "GET /user/marketplace_purchases",
      "GET /user/marketplace_purchases/stubbed",
      "GET /user/memberships/orgs",
      "GET /user/migrations",
      "GET /user/migrations/{migration_id}/repositories",
      "GET /user/orgs",
      "GET /user/packages",
      "GET /user/packages/{package_type}/{package_name}/versions",
      "GET /user/public_emails",
      "GET /user/repos",
      "GET /user/repository_invitations",
      "GET /user/social_accounts",
      "GET /user/ssh_signing_keys",
      "GET /user/starred",
      "GET /user/subscriptions",
      "GET /user/teams",
      "GET /users",
      "GET /users/{username}/events",
      "GET /users/{username}/events/orgs/{org}",
      "GET /users/{username}/events/public",
      "GET /users/{username}/followers",
      "GET /users/{username}/following",
      "GET /users/{username}/gists",
      "GET /users/{username}/gpg_keys",
      "GET /users/{username}/keys",
      "GET /users/{username}/orgs",
      "GET /users/{username}/packages",
      "GET /users/{username}/projects",
      "GET /users/{username}/received_events",
      "GET /users/{username}/received_events/public",
      "GET /users/{username}/repos",
      "GET /users/{username}/social_accounts",
      "GET /users/{username}/ssh_signing_keys",
      "GET /users/{username}/starred",
      "GET /users/{username}/subscriptions"
    ];
    function isPaginatingEndpoint(arg) {
      if (typeof arg === "string") {
        return paginatingEndpoints.includes(arg);
      } else {
        return false;
      }
    }
    function paginateRest(octokit) {
      return {
        paginate: Object.assign(paginate.bind(null, octokit), {
          iterator: iterator.bind(null, octokit)
        })
      };
    }
    paginateRest.VERSION = VERSION;
  }
});

// node_modules/@octokit/plugin-paginate-graphql/dist-node/index.js
var require_dist_node10 = __commonJS({
  "node_modules/@octokit/plugin-paginate-graphql/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      paginateGraphql: () => paginateGraphql
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_core3 = require_dist_node8();
    var generateMessage = (path2, cursorValue) => `The cursor at "${path2.join(
      ","
    )}" did not change its value "${cursorValue}" after a page transition. Please make sure your that your query is set up correctly.`;
    var MissingCursorChange = class extends Error {
      constructor(pageInfo, cursorValue) {
        super(generateMessage(pageInfo.pathInQuery, cursorValue));
        this.pageInfo = pageInfo;
        this.cursorValue = cursorValue;
        this.name = "MissingCursorChangeError";
        if (Error.captureStackTrace) {
          Error.captureStackTrace(this, this.constructor);
        }
      }
    };
    var MissingPageInfo = class extends Error {
      constructor(response) {
        super(
          `No pageInfo property found in response. Please make sure to specify the pageInfo in your query. Response-Data: ${JSON.stringify(
            response,
            null,
            2
          )}`
        );
        this.response = response;
        this.name = "MissingPageInfo";
        if (Error.captureStackTrace) {
          Error.captureStackTrace(this, this.constructor);
        }
      }
    };
    var isObject = (value) => Object.prototype.toString.call(value) === "[object Object]";
    function findPaginatedResourcePath(responseData) {
      const paginatedResourcePath = deepFindPathToProperty(
        responseData,
        "pageInfo"
      );
      if (paginatedResourcePath.length === 0) {
        throw new MissingPageInfo(responseData);
      }
      return paginatedResourcePath;
    }
    var deepFindPathToProperty = (object, searchProp, path2 = []) => {
      for (const key of Object.keys(object)) {
        const currentPath = [...path2, key];
        const currentValue = object[key];
        if (currentValue.hasOwnProperty(searchProp)) {
          return currentPath;
        }
        if (isObject(currentValue)) {
          const result = deepFindPathToProperty(
            currentValue,
            searchProp,
            currentPath
          );
          if (result.length > 0) {
            return result;
          }
        }
      }
      return [];
    };
    var get = (object, path2) => {
      return path2.reduce((current, nextProperty) => current[nextProperty], object);
    };
    var set = (object, path2, mutator) => {
      const lastProperty = path2[path2.length - 1];
      const parentPath = [...path2].slice(0, -1);
      const parent = get(object, parentPath);
      if (typeof mutator === "function") {
        parent[lastProperty] = mutator(parent[lastProperty]);
      } else {
        parent[lastProperty] = mutator;
      }
    };
    var extractPageInfos = (responseData) => {
      const pageInfoPath = findPaginatedResourcePath(responseData);
      return {
        pathInQuery: pageInfoPath,
        pageInfo: get(responseData, [...pageInfoPath, "pageInfo"])
      };
    };
    var import_core = require_dist_node8();
    var isForwardSearch = (givenPageInfo) => {
      return givenPageInfo.hasOwnProperty("hasNextPage");
    };
    var getCursorFrom = (pageInfo) => isForwardSearch(pageInfo) ? pageInfo.endCursor : pageInfo.startCursor;
    var hasAnotherPage = (pageInfo) => isForwardSearch(pageInfo) ? pageInfo.hasNextPage : pageInfo.hasPreviousPage;
    var createIterator = (octokit) => {
      return (query, initialParameters = {}) => {
        let nextPageExists = true;
        let parameters = { ...initialParameters };
        return {
          [Symbol.asyncIterator]: () => ({
            async next() {
              if (!nextPageExists)
                return { done: true, value: {} };
              const response = await octokit.graphql(
                query,
                parameters
              );
              const pageInfoContext = extractPageInfos(response);
              const nextCursorValue = getCursorFrom(pageInfoContext.pageInfo);
              nextPageExists = hasAnotherPage(pageInfoContext.pageInfo);
              if (nextPageExists && nextCursorValue === parameters.cursor) {
                throw new MissingCursorChange(pageInfoContext, nextCursorValue);
              }
              parameters = {
                ...parameters,
                cursor: nextCursorValue
              };
              return { done: false, value: response };
            }
          })
        };
      };
    };
    var import_core2 = require_dist_node8();
    var mergeResponses = (response1, response2) => {
      if (Object.keys(response1).length === 0) {
        return Object.assign(response1, response2);
      }
      const path2 = findPaginatedResourcePath(response1);
      const nodesPath = [...path2, "nodes"];
      const newNodes = get(response2, nodesPath);
      if (newNodes) {
        set(response1, nodesPath, (values) => {
          return [...values, ...newNodes];
        });
      }
      const edgesPath = [...path2, "edges"];
      const newEdges = get(response2, edgesPath);
      if (newEdges) {
        set(response1, edgesPath, (values) => {
          return [...values, ...newEdges];
        });
      }
      const pageInfoPath = [...path2, "pageInfo"];
      set(response1, pageInfoPath, get(response2, pageInfoPath));
      return response1;
    };
    var createPaginate = (octokit) => {
      const iterator = createIterator(octokit);
      return async (query, initialParameters = {}) => {
        let mergedResponse = {};
        for await (const response of iterator(
          query,
          initialParameters
        )) {
          mergedResponse = mergeResponses(mergedResponse, response);
        }
        return mergedResponse;
      };
    };
    function paginateGraphql(octokit) {
      octokit.graphql;
      return {
        graphql: Object.assign(octokit.graphql, {
          paginate: Object.assign(createPaginate(octokit), {
            iterator: createIterator(octokit)
          })
        })
      };
    }
  }
});

// node_modules/@octokit/plugin-rest-endpoint-methods/dist-node/index.js
var require_dist_node11 = __commonJS({
  "node_modules/@octokit/plugin-rest-endpoint-methods/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      legacyRestEndpointMethods: () => legacyRestEndpointMethods,
      restEndpointMethods: () => restEndpointMethods
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var VERSION = "10.0.0";
    var Endpoints = {
      actions: {
        addCustomLabelsToSelfHostedRunnerForOrg: [
          "POST /orgs/{org}/actions/runners/{runner_id}/labels"
        ],
        addCustomLabelsToSelfHostedRunnerForRepo: [
          "POST /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
        ],
        addSelectedRepoToOrgSecret: [
          "PUT /orgs/{org}/actions/secrets/{secret_name}/repositories/{repository_id}"
        ],
        addSelectedRepoToOrgVariable: [
          "PUT /orgs/{org}/actions/variables/{name}/repositories/{repository_id}"
        ],
        approveWorkflowRun: [
          "POST /repos/{owner}/{repo}/actions/runs/{run_id}/approve"
        ],
        cancelWorkflowRun: [
          "POST /repos/{owner}/{repo}/actions/runs/{run_id}/cancel"
        ],
        createEnvironmentVariable: [
          "POST /repositories/{repository_id}/environments/{environment_name}/variables"
        ],
        createOrUpdateEnvironmentSecret: [
          "PUT /repositories/{repository_id}/environments/{environment_name}/secrets/{secret_name}"
        ],
        createOrUpdateOrgSecret: ["PUT /orgs/{org}/actions/secrets/{secret_name}"],
        createOrUpdateRepoSecret: [
          "PUT /repos/{owner}/{repo}/actions/secrets/{secret_name}"
        ],
        createOrgVariable: ["POST /orgs/{org}/actions/variables"],
        createRegistrationTokenForOrg: [
          "POST /orgs/{org}/actions/runners/registration-token"
        ],
        createRegistrationTokenForRepo: [
          "POST /repos/{owner}/{repo}/actions/runners/registration-token"
        ],
        createRemoveTokenForOrg: ["POST /orgs/{org}/actions/runners/remove-token"],
        createRemoveTokenForRepo: [
          "POST /repos/{owner}/{repo}/actions/runners/remove-token"
        ],
        createRepoVariable: ["POST /repos/{owner}/{repo}/actions/variables"],
        createWorkflowDispatch: [
          "POST /repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches"
        ],
        deleteActionsCacheById: [
          "DELETE /repos/{owner}/{repo}/actions/caches/{cache_id}"
        ],
        deleteActionsCacheByKey: [
          "DELETE /repos/{owner}/{repo}/actions/caches{?key,ref}"
        ],
        deleteArtifact: [
          "DELETE /repos/{owner}/{repo}/actions/artifacts/{artifact_id}"
        ],
        deleteEnvironmentSecret: [
          "DELETE /repositories/{repository_id}/environments/{environment_name}/secrets/{secret_name}"
        ],
        deleteEnvironmentVariable: [
          "DELETE /repositories/{repository_id}/environments/{environment_name}/variables/{name}"
        ],
        deleteOrgSecret: ["DELETE /orgs/{org}/actions/secrets/{secret_name}"],
        deleteOrgVariable: ["DELETE /orgs/{org}/actions/variables/{name}"],
        deleteRepoSecret: [
          "DELETE /repos/{owner}/{repo}/actions/secrets/{secret_name}"
        ],
        deleteRepoVariable: [
          "DELETE /repos/{owner}/{repo}/actions/variables/{name}"
        ],
        deleteSelfHostedRunnerFromOrg: [
          "DELETE /orgs/{org}/actions/runners/{runner_id}"
        ],
        deleteSelfHostedRunnerFromRepo: [
          "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}"
        ],
        deleteWorkflowRun: ["DELETE /repos/{owner}/{repo}/actions/runs/{run_id}"],
        deleteWorkflowRunLogs: [
          "DELETE /repos/{owner}/{repo}/actions/runs/{run_id}/logs"
        ],
        disableSelectedRepositoryGithubActionsOrganization: [
          "DELETE /orgs/{org}/actions/permissions/repositories/{repository_id}"
        ],
        disableWorkflow: [
          "PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/disable"
        ],
        downloadArtifact: [
          "GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}/{archive_format}"
        ],
        downloadJobLogsForWorkflowRun: [
          "GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs"
        ],
        downloadWorkflowRunAttemptLogs: [
          "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/logs"
        ],
        downloadWorkflowRunLogs: [
          "GET /repos/{owner}/{repo}/actions/runs/{run_id}/logs"
        ],
        enableSelectedRepositoryGithubActionsOrganization: [
          "PUT /orgs/{org}/actions/permissions/repositories/{repository_id}"
        ],
        enableWorkflow: [
          "PUT /repos/{owner}/{repo}/actions/workflows/{workflow_id}/enable"
        ],
        generateRunnerJitconfigForOrg: [
          "POST /orgs/{org}/actions/runners/generate-jitconfig"
        ],
        generateRunnerJitconfigForRepo: [
          "POST /repos/{owner}/{repo}/actions/runners/generate-jitconfig"
        ],
        getActionsCacheList: ["GET /repos/{owner}/{repo}/actions/caches"],
        getActionsCacheUsage: ["GET /repos/{owner}/{repo}/actions/cache/usage"],
        getActionsCacheUsageByRepoForOrg: [
          "GET /orgs/{org}/actions/cache/usage-by-repository"
        ],
        getActionsCacheUsageForOrg: ["GET /orgs/{org}/actions/cache/usage"],
        getAllowedActionsOrganization: [
          "GET /orgs/{org}/actions/permissions/selected-actions"
        ],
        getAllowedActionsRepository: [
          "GET /repos/{owner}/{repo}/actions/permissions/selected-actions"
        ],
        getArtifact: ["GET /repos/{owner}/{repo}/actions/artifacts/{artifact_id}"],
        getEnvironmentPublicKey: [
          "GET /repositories/{repository_id}/environments/{environment_name}/secrets/public-key"
        ],
        getEnvironmentSecret: [
          "GET /repositories/{repository_id}/environments/{environment_name}/secrets/{secret_name}"
        ],
        getEnvironmentVariable: [
          "GET /repositories/{repository_id}/environments/{environment_name}/variables/{name}"
        ],
        getGithubActionsDefaultWorkflowPermissionsOrganization: [
          "GET /orgs/{org}/actions/permissions/workflow"
        ],
        getGithubActionsDefaultWorkflowPermissionsRepository: [
          "GET /repos/{owner}/{repo}/actions/permissions/workflow"
        ],
        getGithubActionsPermissionsOrganization: [
          "GET /orgs/{org}/actions/permissions"
        ],
        getGithubActionsPermissionsRepository: [
          "GET /repos/{owner}/{repo}/actions/permissions"
        ],
        getJobForWorkflowRun: ["GET /repos/{owner}/{repo}/actions/jobs/{job_id}"],
        getOrgPublicKey: ["GET /orgs/{org}/actions/secrets/public-key"],
        getOrgSecret: ["GET /orgs/{org}/actions/secrets/{secret_name}"],
        getOrgVariable: ["GET /orgs/{org}/actions/variables/{name}"],
        getPendingDeploymentsForRun: [
          "GET /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments"
        ],
        getRepoPermissions: [
          "GET /repos/{owner}/{repo}/actions/permissions",
          {},
          { renamed: ["actions", "getGithubActionsPermissionsRepository"] }
        ],
        getRepoPublicKey: ["GET /repos/{owner}/{repo}/actions/secrets/public-key"],
        getRepoSecret: ["GET /repos/{owner}/{repo}/actions/secrets/{secret_name}"],
        getRepoVariable: ["GET /repos/{owner}/{repo}/actions/variables/{name}"],
        getReviewsForRun: [
          "GET /repos/{owner}/{repo}/actions/runs/{run_id}/approvals"
        ],
        getSelfHostedRunnerForOrg: ["GET /orgs/{org}/actions/runners/{runner_id}"],
        getSelfHostedRunnerForRepo: [
          "GET /repos/{owner}/{repo}/actions/runners/{runner_id}"
        ],
        getWorkflow: ["GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}"],
        getWorkflowAccessToRepository: [
          "GET /repos/{owner}/{repo}/actions/permissions/access"
        ],
        getWorkflowRun: ["GET /repos/{owner}/{repo}/actions/runs/{run_id}"],
        getWorkflowRunAttempt: [
          "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}"
        ],
        getWorkflowRunUsage: [
          "GET /repos/{owner}/{repo}/actions/runs/{run_id}/timing"
        ],
        getWorkflowUsage: [
          "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/timing"
        ],
        listArtifactsForRepo: ["GET /repos/{owner}/{repo}/actions/artifacts"],
        listEnvironmentSecrets: [
          "GET /repositories/{repository_id}/environments/{environment_name}/secrets"
        ],
        listEnvironmentVariables: [
          "GET /repositories/{repository_id}/environments/{environment_name}/variables"
        ],
        listJobsForWorkflowRun: [
          "GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs"
        ],
        listJobsForWorkflowRunAttempt: [
          "GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{attempt_number}/jobs"
        ],
        listLabelsForSelfHostedRunnerForOrg: [
          "GET /orgs/{org}/actions/runners/{runner_id}/labels"
        ],
        listLabelsForSelfHostedRunnerForRepo: [
          "GET /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
        ],
        listOrgSecrets: ["GET /orgs/{org}/actions/secrets"],
        listOrgVariables: ["GET /orgs/{org}/actions/variables"],
        listRepoOrganizationSecrets: [
          "GET /repos/{owner}/{repo}/actions/organization-secrets"
        ],
        listRepoOrganizationVariables: [
          "GET /repos/{owner}/{repo}/actions/organization-variables"
        ],
        listRepoSecrets: ["GET /repos/{owner}/{repo}/actions/secrets"],
        listRepoVariables: ["GET /repos/{owner}/{repo}/actions/variables"],
        listRepoWorkflows: ["GET /repos/{owner}/{repo}/actions/workflows"],
        listRunnerApplicationsForOrg: ["GET /orgs/{org}/actions/runners/downloads"],
        listRunnerApplicationsForRepo: [
          "GET /repos/{owner}/{repo}/actions/runners/downloads"
        ],
        listSelectedReposForOrgSecret: [
          "GET /orgs/{org}/actions/secrets/{secret_name}/repositories"
        ],
        listSelectedReposForOrgVariable: [
          "GET /orgs/{org}/actions/variables/{name}/repositories"
        ],
        listSelectedRepositoriesEnabledGithubActionsOrganization: [
          "GET /orgs/{org}/actions/permissions/repositories"
        ],
        listSelfHostedRunnersForOrg: ["GET /orgs/{org}/actions/runners"],
        listSelfHostedRunnersForRepo: ["GET /repos/{owner}/{repo}/actions/runners"],
        listWorkflowRunArtifacts: [
          "GET /repos/{owner}/{repo}/actions/runs/{run_id}/artifacts"
        ],
        listWorkflowRuns: [
          "GET /repos/{owner}/{repo}/actions/workflows/{workflow_id}/runs"
        ],
        listWorkflowRunsForRepo: ["GET /repos/{owner}/{repo}/actions/runs"],
        reRunJobForWorkflowRun: [
          "POST /repos/{owner}/{repo}/actions/jobs/{job_id}/rerun"
        ],
        reRunWorkflow: ["POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun"],
        reRunWorkflowFailedJobs: [
          "POST /repos/{owner}/{repo}/actions/runs/{run_id}/rerun-failed-jobs"
        ],
        removeAllCustomLabelsFromSelfHostedRunnerForOrg: [
          "DELETE /orgs/{org}/actions/runners/{runner_id}/labels"
        ],
        removeAllCustomLabelsFromSelfHostedRunnerForRepo: [
          "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
        ],
        removeCustomLabelFromSelfHostedRunnerForOrg: [
          "DELETE /orgs/{org}/actions/runners/{runner_id}/labels/{name}"
        ],
        removeCustomLabelFromSelfHostedRunnerForRepo: [
          "DELETE /repos/{owner}/{repo}/actions/runners/{runner_id}/labels/{name}"
        ],
        removeSelectedRepoFromOrgSecret: [
          "DELETE /orgs/{org}/actions/secrets/{secret_name}/repositories/{repository_id}"
        ],
        removeSelectedRepoFromOrgVariable: [
          "DELETE /orgs/{org}/actions/variables/{name}/repositories/{repository_id}"
        ],
        reviewCustomGatesForRun: [
          "POST /repos/{owner}/{repo}/actions/runs/{run_id}/deployment_protection_rule"
        ],
        reviewPendingDeploymentsForRun: [
          "POST /repos/{owner}/{repo}/actions/runs/{run_id}/pending_deployments"
        ],
        setAllowedActionsOrganization: [
          "PUT /orgs/{org}/actions/permissions/selected-actions"
        ],
        setAllowedActionsRepository: [
          "PUT /repos/{owner}/{repo}/actions/permissions/selected-actions"
        ],
        setCustomLabelsForSelfHostedRunnerForOrg: [
          "PUT /orgs/{org}/actions/runners/{runner_id}/labels"
        ],
        setCustomLabelsForSelfHostedRunnerForRepo: [
          "PUT /repos/{owner}/{repo}/actions/runners/{runner_id}/labels"
        ],
        setGithubActionsDefaultWorkflowPermissionsOrganization: [
          "PUT /orgs/{org}/actions/permissions/workflow"
        ],
        setGithubActionsDefaultWorkflowPermissionsRepository: [
          "PUT /repos/{owner}/{repo}/actions/permissions/workflow"
        ],
        setGithubActionsPermissionsOrganization: [
          "PUT /orgs/{org}/actions/permissions"
        ],
        setGithubActionsPermissionsRepository: [
          "PUT /repos/{owner}/{repo}/actions/permissions"
        ],
        setSelectedReposForOrgSecret: [
          "PUT /orgs/{org}/actions/secrets/{secret_name}/repositories"
        ],
        setSelectedReposForOrgVariable: [
          "PUT /orgs/{org}/actions/variables/{name}/repositories"
        ],
        setSelectedRepositoriesEnabledGithubActionsOrganization: [
          "PUT /orgs/{org}/actions/permissions/repositories"
        ],
        setWorkflowAccessToRepository: [
          "PUT /repos/{owner}/{repo}/actions/permissions/access"
        ],
        updateEnvironmentVariable: [
          "PATCH /repositories/{repository_id}/environments/{environment_name}/variables/{name}"
        ],
        updateOrgVariable: ["PATCH /orgs/{org}/actions/variables/{name}"],
        updateRepoVariable: [
          "PATCH /repos/{owner}/{repo}/actions/variables/{name}"
        ]
      },
      activity: {
        checkRepoIsStarredByAuthenticatedUser: ["GET /user/starred/{owner}/{repo}"],
        deleteRepoSubscription: ["DELETE /repos/{owner}/{repo}/subscription"],
        deleteThreadSubscription: [
          "DELETE /notifications/threads/{thread_id}/subscription"
        ],
        getFeeds: ["GET /feeds"],
        getRepoSubscription: ["GET /repos/{owner}/{repo}/subscription"],
        getThread: ["GET /notifications/threads/{thread_id}"],
        getThreadSubscriptionForAuthenticatedUser: [
          "GET /notifications/threads/{thread_id}/subscription"
        ],
        listEventsForAuthenticatedUser: ["GET /users/{username}/events"],
        listNotificationsForAuthenticatedUser: ["GET /notifications"],
        listOrgEventsForAuthenticatedUser: [
          "GET /users/{username}/events/orgs/{org}"
        ],
        listPublicEvents: ["GET /events"],
        listPublicEventsForRepoNetwork: ["GET /networks/{owner}/{repo}/events"],
        listPublicEventsForUser: ["GET /users/{username}/events/public"],
        listPublicOrgEvents: ["GET /orgs/{org}/events"],
        listReceivedEventsForUser: ["GET /users/{username}/received_events"],
        listReceivedPublicEventsForUser: [
          "GET /users/{username}/received_events/public"
        ],
        listRepoEvents: ["GET /repos/{owner}/{repo}/events"],
        listRepoNotificationsForAuthenticatedUser: [
          "GET /repos/{owner}/{repo}/notifications"
        ],
        listReposStarredByAuthenticatedUser: ["GET /user/starred"],
        listReposStarredByUser: ["GET /users/{username}/starred"],
        listReposWatchedByUser: ["GET /users/{username}/subscriptions"],
        listStargazersForRepo: ["GET /repos/{owner}/{repo}/stargazers"],
        listWatchedReposForAuthenticatedUser: ["GET /user/subscriptions"],
        listWatchersForRepo: ["GET /repos/{owner}/{repo}/subscribers"],
        markNotificationsAsRead: ["PUT /notifications"],
        markRepoNotificationsAsRead: ["PUT /repos/{owner}/{repo}/notifications"],
        markThreadAsRead: ["PATCH /notifications/threads/{thread_id}"],
        setRepoSubscription: ["PUT /repos/{owner}/{repo}/subscription"],
        setThreadSubscription: [
          "PUT /notifications/threads/{thread_id}/subscription"
        ],
        starRepoForAuthenticatedUser: ["PUT /user/starred/{owner}/{repo}"],
        unstarRepoForAuthenticatedUser: ["DELETE /user/starred/{owner}/{repo}"]
      },
      apps: {
        addRepoToInstallation: [
          "PUT /user/installations/{installation_id}/repositories/{repository_id}",
          {},
          { renamed: ["apps", "addRepoToInstallationForAuthenticatedUser"] }
        ],
        addRepoToInstallationForAuthenticatedUser: [
          "PUT /user/installations/{installation_id}/repositories/{repository_id}"
        ],
        checkToken: ["POST /applications/{client_id}/token"],
        createFromManifest: ["POST /app-manifests/{code}/conversions"],
        createInstallationAccessToken: [
          "POST /app/installations/{installation_id}/access_tokens"
        ],
        deleteAuthorization: ["DELETE /applications/{client_id}/grant"],
        deleteInstallation: ["DELETE /app/installations/{installation_id}"],
        deleteToken: ["DELETE /applications/{client_id}/token"],
        getAuthenticated: ["GET /app"],
        getBySlug: ["GET /apps/{app_slug}"],
        getInstallation: ["GET /app/installations/{installation_id}"],
        getOrgInstallation: ["GET /orgs/{org}/installation"],
        getRepoInstallation: ["GET /repos/{owner}/{repo}/installation"],
        getSubscriptionPlanForAccount: [
          "GET /marketplace_listing/accounts/{account_id}"
        ],
        getSubscriptionPlanForAccountStubbed: [
          "GET /marketplace_listing/stubbed/accounts/{account_id}"
        ],
        getUserInstallation: ["GET /users/{username}/installation"],
        getWebhookConfigForApp: ["GET /app/hook/config"],
        getWebhookDelivery: ["GET /app/hook/deliveries/{delivery_id}"],
        listAccountsForPlan: ["GET /marketplace_listing/plans/{plan_id}/accounts"],
        listAccountsForPlanStubbed: [
          "GET /marketplace_listing/stubbed/plans/{plan_id}/accounts"
        ],
        listInstallationReposForAuthenticatedUser: [
          "GET /user/installations/{installation_id}/repositories"
        ],
        listInstallationRequestsForAuthenticatedApp: [
          "GET /app/installation-requests"
        ],
        listInstallations: ["GET /app/installations"],
        listInstallationsForAuthenticatedUser: ["GET /user/installations"],
        listPlans: ["GET /marketplace_listing/plans"],
        listPlansStubbed: ["GET /marketplace_listing/stubbed/plans"],
        listReposAccessibleToInstallation: ["GET /installation/repositories"],
        listSubscriptionsForAuthenticatedUser: ["GET /user/marketplace_purchases"],
        listSubscriptionsForAuthenticatedUserStubbed: [
          "GET /user/marketplace_purchases/stubbed"
        ],
        listWebhookDeliveries: ["GET /app/hook/deliveries"],
        redeliverWebhookDelivery: [
          "POST /app/hook/deliveries/{delivery_id}/attempts"
        ],
        removeRepoFromInstallation: [
          "DELETE /user/installations/{installation_id}/repositories/{repository_id}",
          {},
          { renamed: ["apps", "removeRepoFromInstallationForAuthenticatedUser"] }
        ],
        removeRepoFromInstallationForAuthenticatedUser: [
          "DELETE /user/installations/{installation_id}/repositories/{repository_id}"
        ],
        resetToken: ["PATCH /applications/{client_id}/token"],
        revokeInstallationAccessToken: ["DELETE /installation/token"],
        scopeToken: ["POST /applications/{client_id}/token/scoped"],
        suspendInstallation: ["PUT /app/installations/{installation_id}/suspended"],
        unsuspendInstallation: [
          "DELETE /app/installations/{installation_id}/suspended"
        ],
        updateWebhookConfigForApp: ["PATCH /app/hook/config"]
      },
      billing: {
        getGithubActionsBillingOrg: ["GET /orgs/{org}/settings/billing/actions"],
        getGithubActionsBillingUser: [
          "GET /users/{username}/settings/billing/actions"
        ],
        getGithubPackagesBillingOrg: ["GET /orgs/{org}/settings/billing/packages"],
        getGithubPackagesBillingUser: [
          "GET /users/{username}/settings/billing/packages"
        ],
        getSharedStorageBillingOrg: [
          "GET /orgs/{org}/settings/billing/shared-storage"
        ],
        getSharedStorageBillingUser: [
          "GET /users/{username}/settings/billing/shared-storage"
        ]
      },
      checks: {
        create: ["POST /repos/{owner}/{repo}/check-runs"],
        createSuite: ["POST /repos/{owner}/{repo}/check-suites"],
        get: ["GET /repos/{owner}/{repo}/check-runs/{check_run_id}"],
        getSuite: ["GET /repos/{owner}/{repo}/check-suites/{check_suite_id}"],
        listAnnotations: [
          "GET /repos/{owner}/{repo}/check-runs/{check_run_id}/annotations"
        ],
        listForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/check-runs"],
        listForSuite: [
          "GET /repos/{owner}/{repo}/check-suites/{check_suite_id}/check-runs"
        ],
        listSuitesForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/check-suites"],
        rerequestRun: [
          "POST /repos/{owner}/{repo}/check-runs/{check_run_id}/rerequest"
        ],
        rerequestSuite: [
          "POST /repos/{owner}/{repo}/check-suites/{check_suite_id}/rerequest"
        ],
        setSuitesPreferences: [
          "PATCH /repos/{owner}/{repo}/check-suites/preferences"
        ],
        update: ["PATCH /repos/{owner}/{repo}/check-runs/{check_run_id}"]
      },
      codeScanning: {
        deleteAnalysis: [
          "DELETE /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}{?confirm_delete}"
        ],
        getAlert: [
          "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}",
          {},
          { renamedParameters: { alert_id: "alert_number" } }
        ],
        getAnalysis: [
          "GET /repos/{owner}/{repo}/code-scanning/analyses/{analysis_id}"
        ],
        getCodeqlDatabase: [
          "GET /repos/{owner}/{repo}/code-scanning/codeql/databases/{language}"
        ],
        getDefaultSetup: ["GET /repos/{owner}/{repo}/code-scanning/default-setup"],
        getSarif: ["GET /repos/{owner}/{repo}/code-scanning/sarifs/{sarif_id}"],
        listAlertInstances: [
          "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances"
        ],
        listAlertsForOrg: ["GET /orgs/{org}/code-scanning/alerts"],
        listAlertsForRepo: ["GET /repos/{owner}/{repo}/code-scanning/alerts"],
        listAlertsInstances: [
          "GET /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}/instances",
          {},
          { renamed: ["codeScanning", "listAlertInstances"] }
        ],
        listCodeqlDatabases: [
          "GET /repos/{owner}/{repo}/code-scanning/codeql/databases"
        ],
        listRecentAnalyses: ["GET /repos/{owner}/{repo}/code-scanning/analyses"],
        updateAlert: [
          "PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
        ],
        updateDefaultSetup: [
          "PATCH /repos/{owner}/{repo}/code-scanning/default-setup"
        ],
        uploadSarif: ["POST /repos/{owner}/{repo}/code-scanning/sarifs"]
      },
      codesOfConduct: {
        getAllCodesOfConduct: ["GET /codes_of_conduct"],
        getConductCode: ["GET /codes_of_conduct/{key}"]
      },
      codespaces: {
        addRepositoryForSecretForAuthenticatedUser: [
          "PUT /user/codespaces/secrets/{secret_name}/repositories/{repository_id}"
        ],
        addSelectedRepoToOrgSecret: [
          "PUT /orgs/{org}/codespaces/secrets/{secret_name}/repositories/{repository_id}"
        ],
        codespaceMachinesForAuthenticatedUser: [
          "GET /user/codespaces/{codespace_name}/machines"
        ],
        createForAuthenticatedUser: ["POST /user/codespaces"],
        createOrUpdateOrgSecret: [
          "PUT /orgs/{org}/codespaces/secrets/{secret_name}"
        ],
        createOrUpdateRepoSecret: [
          "PUT /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
        ],
        createOrUpdateSecretForAuthenticatedUser: [
          "PUT /user/codespaces/secrets/{secret_name}"
        ],
        createWithPrForAuthenticatedUser: [
          "POST /repos/{owner}/{repo}/pulls/{pull_number}/codespaces"
        ],
        createWithRepoForAuthenticatedUser: [
          "POST /repos/{owner}/{repo}/codespaces"
        ],
        deleteForAuthenticatedUser: ["DELETE /user/codespaces/{codespace_name}"],
        deleteFromOrganization: [
          "DELETE /orgs/{org}/members/{username}/codespaces/{codespace_name}"
        ],
        deleteOrgSecret: ["DELETE /orgs/{org}/codespaces/secrets/{secret_name}"],
        deleteRepoSecret: [
          "DELETE /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
        ],
        deleteSecretForAuthenticatedUser: [
          "DELETE /user/codespaces/secrets/{secret_name}"
        ],
        exportForAuthenticatedUser: [
          "POST /user/codespaces/{codespace_name}/exports"
        ],
        getCodespacesForUserInOrg: [
          "GET /orgs/{org}/members/{username}/codespaces"
        ],
        getExportDetailsForAuthenticatedUser: [
          "GET /user/codespaces/{codespace_name}/exports/{export_id}"
        ],
        getForAuthenticatedUser: ["GET /user/codespaces/{codespace_name}"],
        getOrgPublicKey: ["GET /orgs/{org}/codespaces/secrets/public-key"],
        getOrgSecret: ["GET /orgs/{org}/codespaces/secrets/{secret_name}"],
        getPublicKeyForAuthenticatedUser: [
          "GET /user/codespaces/secrets/public-key"
        ],
        getRepoPublicKey: [
          "GET /repos/{owner}/{repo}/codespaces/secrets/public-key"
        ],
        getRepoSecret: [
          "GET /repos/{owner}/{repo}/codespaces/secrets/{secret_name}"
        ],
        getSecretForAuthenticatedUser: [
          "GET /user/codespaces/secrets/{secret_name}"
        ],
        listDevcontainersInRepositoryForAuthenticatedUser: [
          "GET /repos/{owner}/{repo}/codespaces/devcontainers"
        ],
        listForAuthenticatedUser: ["GET /user/codespaces"],
        listInOrganization: [
          "GET /orgs/{org}/codespaces",
          {},
          { renamedParameters: { org_id: "org" } }
        ],
        listInRepositoryForAuthenticatedUser: [
          "GET /repos/{owner}/{repo}/codespaces"
        ],
        listOrgSecrets: ["GET /orgs/{org}/codespaces/secrets"],
        listRepoSecrets: ["GET /repos/{owner}/{repo}/codespaces/secrets"],
        listRepositoriesForSecretForAuthenticatedUser: [
          "GET /user/codespaces/secrets/{secret_name}/repositories"
        ],
        listSecretsForAuthenticatedUser: ["GET /user/codespaces/secrets"],
        listSelectedReposForOrgSecret: [
          "GET /orgs/{org}/codespaces/secrets/{secret_name}/repositories"
        ],
        preFlightWithRepoForAuthenticatedUser: [
          "GET /repos/{owner}/{repo}/codespaces/new"
        ],
        publishForAuthenticatedUser: [
          "POST /user/codespaces/{codespace_name}/publish"
        ],
        removeRepositoryForSecretForAuthenticatedUser: [
          "DELETE /user/codespaces/secrets/{secret_name}/repositories/{repository_id}"
        ],
        removeSelectedRepoFromOrgSecret: [
          "DELETE /orgs/{org}/codespaces/secrets/{secret_name}/repositories/{repository_id}"
        ],
        repoMachinesForAuthenticatedUser: [
          "GET /repos/{owner}/{repo}/codespaces/machines"
        ],
        setRepositoriesForSecretForAuthenticatedUser: [
          "PUT /user/codespaces/secrets/{secret_name}/repositories"
        ],
        setSelectedReposForOrgSecret: [
          "PUT /orgs/{org}/codespaces/secrets/{secret_name}/repositories"
        ],
        startForAuthenticatedUser: ["POST /user/codespaces/{codespace_name}/start"],
        stopForAuthenticatedUser: ["POST /user/codespaces/{codespace_name}/stop"],
        stopInOrganization: [
          "POST /orgs/{org}/members/{username}/codespaces/{codespace_name}/stop"
        ],
        updateForAuthenticatedUser: ["PATCH /user/codespaces/{codespace_name}"]
      },
      copilot: {
        addCopilotForBusinessSeatsForTeams: [
          "POST /orgs/{org}/copilot/billing/selected_teams"
        ],
        addCopilotForBusinessSeatsForUsers: [
          "POST /orgs/{org}/copilot/billing/selected_users"
        ],
        cancelCopilotSeatAssignmentForTeams: [
          "DELETE /orgs/{org}/copilot/billing/selected_teams"
        ],
        cancelCopilotSeatAssignmentForUsers: [
          "DELETE /orgs/{org}/copilot/billing/selected_users"
        ],
        getCopilotOrganizationDetails: ["GET /orgs/{org}/copilot/billing"],
        getCopilotSeatAssignmentDetailsForUser: [
          "GET /orgs/{org}/members/{username}/copilot"
        ],
        listCopilotSeats: ["GET /orgs/{org}/copilot/billing/seats"]
      },
      dependabot: {
        addSelectedRepoToOrgSecret: [
          "PUT /orgs/{org}/dependabot/secrets/{secret_name}/repositories/{repository_id}"
        ],
        createOrUpdateOrgSecret: [
          "PUT /orgs/{org}/dependabot/secrets/{secret_name}"
        ],
        createOrUpdateRepoSecret: [
          "PUT /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
        ],
        deleteOrgSecret: ["DELETE /orgs/{org}/dependabot/secrets/{secret_name}"],
        deleteRepoSecret: [
          "DELETE /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
        ],
        getAlert: ["GET /repos/{owner}/{repo}/dependabot/alerts/{alert_number}"],
        getOrgPublicKey: ["GET /orgs/{org}/dependabot/secrets/public-key"],
        getOrgSecret: ["GET /orgs/{org}/dependabot/secrets/{secret_name}"],
        getRepoPublicKey: [
          "GET /repos/{owner}/{repo}/dependabot/secrets/public-key"
        ],
        getRepoSecret: [
          "GET /repos/{owner}/{repo}/dependabot/secrets/{secret_name}"
        ],
        listAlertsForEnterprise: [
          "GET /enterprises/{enterprise}/dependabot/alerts"
        ],
        listAlertsForOrg: ["GET /orgs/{org}/dependabot/alerts"],
        listAlertsForRepo: ["GET /repos/{owner}/{repo}/dependabot/alerts"],
        listOrgSecrets: ["GET /orgs/{org}/dependabot/secrets"],
        listRepoSecrets: ["GET /repos/{owner}/{repo}/dependabot/secrets"],
        listSelectedReposForOrgSecret: [
          "GET /orgs/{org}/dependabot/secrets/{secret_name}/repositories"
        ],
        removeSelectedRepoFromOrgSecret: [
          "DELETE /orgs/{org}/dependabot/secrets/{secret_name}/repositories/{repository_id}"
        ],
        setSelectedReposForOrgSecret: [
          "PUT /orgs/{org}/dependabot/secrets/{secret_name}/repositories"
        ],
        updateAlert: [
          "PATCH /repos/{owner}/{repo}/dependabot/alerts/{alert_number}"
        ]
      },
      dependencyGraph: {
        createRepositorySnapshot: [
          "POST /repos/{owner}/{repo}/dependency-graph/snapshots"
        ],
        diffRange: [
          "GET /repos/{owner}/{repo}/dependency-graph/compare/{basehead}"
        ],
        exportSbom: ["GET /repos/{owner}/{repo}/dependency-graph/sbom"]
      },
      emojis: { get: ["GET /emojis"] },
      gists: {
        checkIsStarred: ["GET /gists/{gist_id}/star"],
        create: ["POST /gists"],
        createComment: ["POST /gists/{gist_id}/comments"],
        delete: ["DELETE /gists/{gist_id}"],
        deleteComment: ["DELETE /gists/{gist_id}/comments/{comment_id}"],
        fork: ["POST /gists/{gist_id}/forks"],
        get: ["GET /gists/{gist_id}"],
        getComment: ["GET /gists/{gist_id}/comments/{comment_id}"],
        getRevision: ["GET /gists/{gist_id}/{sha}"],
        list: ["GET /gists"],
        listComments: ["GET /gists/{gist_id}/comments"],
        listCommits: ["GET /gists/{gist_id}/commits"],
        listForUser: ["GET /users/{username}/gists"],
        listForks: ["GET /gists/{gist_id}/forks"],
        listPublic: ["GET /gists/public"],
        listStarred: ["GET /gists/starred"],
        star: ["PUT /gists/{gist_id}/star"],
        unstar: ["DELETE /gists/{gist_id}/star"],
        update: ["PATCH /gists/{gist_id}"],
        updateComment: ["PATCH /gists/{gist_id}/comments/{comment_id}"]
      },
      git: {
        createBlob: ["POST /repos/{owner}/{repo}/git/blobs"],
        createCommit: ["POST /repos/{owner}/{repo}/git/commits"],
        createRef: ["POST /repos/{owner}/{repo}/git/refs"],
        createTag: ["POST /repos/{owner}/{repo}/git/tags"],
        createTree: ["POST /repos/{owner}/{repo}/git/trees"],
        deleteRef: ["DELETE /repos/{owner}/{repo}/git/refs/{ref}"],
        getBlob: ["GET /repos/{owner}/{repo}/git/blobs/{file_sha}"],
        getCommit: ["GET /repos/{owner}/{repo}/git/commits/{commit_sha}"],
        getRef: ["GET /repos/{owner}/{repo}/git/ref/{ref}"],
        getTag: ["GET /repos/{owner}/{repo}/git/tags/{tag_sha}"],
        getTree: ["GET /repos/{owner}/{repo}/git/trees/{tree_sha}"],
        listMatchingRefs: ["GET /repos/{owner}/{repo}/git/matching-refs/{ref}"],
        updateRef: ["PATCH /repos/{owner}/{repo}/git/refs/{ref}"]
      },
      gitignore: {
        getAllTemplates: ["GET /gitignore/templates"],
        getTemplate: ["GET /gitignore/templates/{name}"]
      },
      interactions: {
        getRestrictionsForAuthenticatedUser: ["GET /user/interaction-limits"],
        getRestrictionsForOrg: ["GET /orgs/{org}/interaction-limits"],
        getRestrictionsForRepo: ["GET /repos/{owner}/{repo}/interaction-limits"],
        getRestrictionsForYourPublicRepos: [
          "GET /user/interaction-limits",
          {},
          { renamed: ["interactions", "getRestrictionsForAuthenticatedUser"] }
        ],
        removeRestrictionsForAuthenticatedUser: ["DELETE /user/interaction-limits"],
        removeRestrictionsForOrg: ["DELETE /orgs/{org}/interaction-limits"],
        removeRestrictionsForRepo: [
          "DELETE /repos/{owner}/{repo}/interaction-limits"
        ],
        removeRestrictionsForYourPublicRepos: [
          "DELETE /user/interaction-limits",
          {},
          { renamed: ["interactions", "removeRestrictionsForAuthenticatedUser"] }
        ],
        setRestrictionsForAuthenticatedUser: ["PUT /user/interaction-limits"],
        setRestrictionsForOrg: ["PUT /orgs/{org}/interaction-limits"],
        setRestrictionsForRepo: ["PUT /repos/{owner}/{repo}/interaction-limits"],
        setRestrictionsForYourPublicRepos: [
          "PUT /user/interaction-limits",
          {},
          { renamed: ["interactions", "setRestrictionsForAuthenticatedUser"] }
        ]
      },
      issues: {
        addAssignees: [
          "POST /repos/{owner}/{repo}/issues/{issue_number}/assignees"
        ],
        addLabels: ["POST /repos/{owner}/{repo}/issues/{issue_number}/labels"],
        checkUserCanBeAssigned: ["GET /repos/{owner}/{repo}/assignees/{assignee}"],
        checkUserCanBeAssignedToIssue: [
          "GET /repos/{owner}/{repo}/issues/{issue_number}/assignees/{assignee}"
        ],
        create: ["POST /repos/{owner}/{repo}/issues"],
        createComment: [
          "POST /repos/{owner}/{repo}/issues/{issue_number}/comments"
        ],
        createLabel: ["POST /repos/{owner}/{repo}/labels"],
        createMilestone: ["POST /repos/{owner}/{repo}/milestones"],
        deleteComment: [
          "DELETE /repos/{owner}/{repo}/issues/comments/{comment_id}"
        ],
        deleteLabel: ["DELETE /repos/{owner}/{repo}/labels/{name}"],
        deleteMilestone: [
          "DELETE /repos/{owner}/{repo}/milestones/{milestone_number}"
        ],
        get: ["GET /repos/{owner}/{repo}/issues/{issue_number}"],
        getComment: ["GET /repos/{owner}/{repo}/issues/comments/{comment_id}"],
        getEvent: ["GET /repos/{owner}/{repo}/issues/events/{event_id}"],
        getLabel: ["GET /repos/{owner}/{repo}/labels/{name}"],
        getMilestone: ["GET /repos/{owner}/{repo}/milestones/{milestone_number}"],
        list: ["GET /issues"],
        listAssignees: ["GET /repos/{owner}/{repo}/assignees"],
        listComments: ["GET /repos/{owner}/{repo}/issues/{issue_number}/comments"],
        listCommentsForRepo: ["GET /repos/{owner}/{repo}/issues/comments"],
        listEvents: ["GET /repos/{owner}/{repo}/issues/{issue_number}/events"],
        listEventsForRepo: ["GET /repos/{owner}/{repo}/issues/events"],
        listEventsForTimeline: [
          "GET /repos/{owner}/{repo}/issues/{issue_number}/timeline"
        ],
        listForAuthenticatedUser: ["GET /user/issues"],
        listForOrg: ["GET /orgs/{org}/issues"],
        listForRepo: ["GET /repos/{owner}/{repo}/issues"],
        listLabelsForMilestone: [
          "GET /repos/{owner}/{repo}/milestones/{milestone_number}/labels"
        ],
        listLabelsForRepo: ["GET /repos/{owner}/{repo}/labels"],
        listLabelsOnIssue: [
          "GET /repos/{owner}/{repo}/issues/{issue_number}/labels"
        ],
        listMilestones: ["GET /repos/{owner}/{repo}/milestones"],
        lock: ["PUT /repos/{owner}/{repo}/issues/{issue_number}/lock"],
        removeAllLabels: [
          "DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels"
        ],
        removeAssignees: [
          "DELETE /repos/{owner}/{repo}/issues/{issue_number}/assignees"
        ],
        removeLabel: [
          "DELETE /repos/{owner}/{repo}/issues/{issue_number}/labels/{name}"
        ],
        setLabels: ["PUT /repos/{owner}/{repo}/issues/{issue_number}/labels"],
        unlock: ["DELETE /repos/{owner}/{repo}/issues/{issue_number}/lock"],
        update: ["PATCH /repos/{owner}/{repo}/issues/{issue_number}"],
        updateComment: ["PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}"],
        updateLabel: ["PATCH /repos/{owner}/{repo}/labels/{name}"],
        updateMilestone: [
          "PATCH /repos/{owner}/{repo}/milestones/{milestone_number}"
        ]
      },
      licenses: {
        get: ["GET /licenses/{license}"],
        getAllCommonlyUsed: ["GET /licenses"],
        getForRepo: ["GET /repos/{owner}/{repo}/license"]
      },
      markdown: {
        render: ["POST /markdown"],
        renderRaw: [
          "POST /markdown/raw",
          { headers: { "content-type": "text/plain; charset=utf-8" } }
        ]
      },
      meta: {
        get: ["GET /meta"],
        getAllVersions: ["GET /versions"],
        getOctocat: ["GET /octocat"],
        getZen: ["GET /zen"],
        root: ["GET /"]
      },
      migrations: {
        cancelImport: ["DELETE /repos/{owner}/{repo}/import"],
        deleteArchiveForAuthenticatedUser: [
          "DELETE /user/migrations/{migration_id}/archive"
        ],
        deleteArchiveForOrg: [
          "DELETE /orgs/{org}/migrations/{migration_id}/archive"
        ],
        downloadArchiveForOrg: [
          "GET /orgs/{org}/migrations/{migration_id}/archive"
        ],
        getArchiveForAuthenticatedUser: [
          "GET /user/migrations/{migration_id}/archive"
        ],
        getCommitAuthors: ["GET /repos/{owner}/{repo}/import/authors"],
        getImportStatus: ["GET /repos/{owner}/{repo}/import"],
        getLargeFiles: ["GET /repos/{owner}/{repo}/import/large_files"],
        getStatusForAuthenticatedUser: ["GET /user/migrations/{migration_id}"],
        getStatusForOrg: ["GET /orgs/{org}/migrations/{migration_id}"],
        listForAuthenticatedUser: ["GET /user/migrations"],
        listForOrg: ["GET /orgs/{org}/migrations"],
        listReposForAuthenticatedUser: [
          "GET /user/migrations/{migration_id}/repositories"
        ],
        listReposForOrg: ["GET /orgs/{org}/migrations/{migration_id}/repositories"],
        listReposForUser: [
          "GET /user/migrations/{migration_id}/repositories",
          {},
          { renamed: ["migrations", "listReposForAuthenticatedUser"] }
        ],
        mapCommitAuthor: ["PATCH /repos/{owner}/{repo}/import/authors/{author_id}"],
        setLfsPreference: ["PATCH /repos/{owner}/{repo}/import/lfs"],
        startForAuthenticatedUser: ["POST /user/migrations"],
        startForOrg: ["POST /orgs/{org}/migrations"],
        startImport: ["PUT /repos/{owner}/{repo}/import"],
        unlockRepoForAuthenticatedUser: [
          "DELETE /user/migrations/{migration_id}/repos/{repo_name}/lock"
        ],
        unlockRepoForOrg: [
          "DELETE /orgs/{org}/migrations/{migration_id}/repos/{repo_name}/lock"
        ],
        updateImport: ["PATCH /repos/{owner}/{repo}/import"]
      },
      orgs: {
        addSecurityManagerTeam: [
          "PUT /orgs/{org}/security-managers/teams/{team_slug}"
        ],
        blockUser: ["PUT /orgs/{org}/blocks/{username}"],
        cancelInvitation: ["DELETE /orgs/{org}/invitations/{invitation_id}"],
        checkBlockedUser: ["GET /orgs/{org}/blocks/{username}"],
        checkMembershipForUser: ["GET /orgs/{org}/members/{username}"],
        checkPublicMembershipForUser: ["GET /orgs/{org}/public_members/{username}"],
        convertMemberToOutsideCollaborator: [
          "PUT /orgs/{org}/outside_collaborators/{username}"
        ],
        createInvitation: ["POST /orgs/{org}/invitations"],
        createWebhook: ["POST /orgs/{org}/hooks"],
        delete: ["DELETE /orgs/{org}"],
        deleteWebhook: ["DELETE /orgs/{org}/hooks/{hook_id}"],
        enableOrDisableSecurityProductOnAllOrgRepos: [
          "POST /orgs/{org}/{security_product}/{enablement}"
        ],
        get: ["GET /orgs/{org}"],
        getMembershipForAuthenticatedUser: ["GET /user/memberships/orgs/{org}"],
        getMembershipForUser: ["GET /orgs/{org}/memberships/{username}"],
        getWebhook: ["GET /orgs/{org}/hooks/{hook_id}"],
        getWebhookConfigForOrg: ["GET /orgs/{org}/hooks/{hook_id}/config"],
        getWebhookDelivery: [
          "GET /orgs/{org}/hooks/{hook_id}/deliveries/{delivery_id}"
        ],
        list: ["GET /organizations"],
        listAppInstallations: ["GET /orgs/{org}/installations"],
        listBlockedUsers: ["GET /orgs/{org}/blocks"],
        listFailedInvitations: ["GET /orgs/{org}/failed_invitations"],
        listForAuthenticatedUser: ["GET /user/orgs"],
        listForUser: ["GET /users/{username}/orgs"],
        listInvitationTeams: ["GET /orgs/{org}/invitations/{invitation_id}/teams"],
        listMembers: ["GET /orgs/{org}/members"],
        listMembershipsForAuthenticatedUser: ["GET /user/memberships/orgs"],
        listOutsideCollaborators: ["GET /orgs/{org}/outside_collaborators"],
        listPatGrantRepositories: [
          "GET /orgs/{org}/personal-access-tokens/{pat_id}/repositories"
        ],
        listPatGrantRequestRepositories: [
          "GET /orgs/{org}/personal-access-token-requests/{pat_request_id}/repositories"
        ],
        listPatGrantRequests: ["GET /orgs/{org}/personal-access-token-requests"],
        listPatGrants: ["GET /orgs/{org}/personal-access-tokens"],
        listPendingInvitations: ["GET /orgs/{org}/invitations"],
        listPublicMembers: ["GET /orgs/{org}/public_members"],
        listSecurityManagerTeams: ["GET /orgs/{org}/security-managers"],
        listWebhookDeliveries: ["GET /orgs/{org}/hooks/{hook_id}/deliveries"],
        listWebhooks: ["GET /orgs/{org}/hooks"],
        pingWebhook: ["POST /orgs/{org}/hooks/{hook_id}/pings"],
        redeliverWebhookDelivery: [
          "POST /orgs/{org}/hooks/{hook_id}/deliveries/{delivery_id}/attempts"
        ],
        removeMember: ["DELETE /orgs/{org}/members/{username}"],
        removeMembershipForUser: ["DELETE /orgs/{org}/memberships/{username}"],
        removeOutsideCollaborator: [
          "DELETE /orgs/{org}/outside_collaborators/{username}"
        ],
        removePublicMembershipForAuthenticatedUser: [
          "DELETE /orgs/{org}/public_members/{username}"
        ],
        removeSecurityManagerTeam: [
          "DELETE /orgs/{org}/security-managers/teams/{team_slug}"
        ],
        reviewPatGrantRequest: [
          "POST /orgs/{org}/personal-access-token-requests/{pat_request_id}"
        ],
        reviewPatGrantRequestsInBulk: [
          "POST /orgs/{org}/personal-access-token-requests"
        ],
        setMembershipForUser: ["PUT /orgs/{org}/memberships/{username}"],
        setPublicMembershipForAuthenticatedUser: [
          "PUT /orgs/{org}/public_members/{username}"
        ],
        unblockUser: ["DELETE /orgs/{org}/blocks/{username}"],
        update: ["PATCH /orgs/{org}"],
        updateMembershipForAuthenticatedUser: [
          "PATCH /user/memberships/orgs/{org}"
        ],
        updatePatAccess: ["POST /orgs/{org}/personal-access-tokens/{pat_id}"],
        updatePatAccesses: ["POST /orgs/{org}/personal-access-tokens"],
        updateWebhook: ["PATCH /orgs/{org}/hooks/{hook_id}"],
        updateWebhookConfigForOrg: ["PATCH /orgs/{org}/hooks/{hook_id}/config"]
      },
      packages: {
        deletePackageForAuthenticatedUser: [
          "DELETE /user/packages/{package_type}/{package_name}"
        ],
        deletePackageForOrg: [
          "DELETE /orgs/{org}/packages/{package_type}/{package_name}"
        ],
        deletePackageForUser: [
          "DELETE /users/{username}/packages/{package_type}/{package_name}"
        ],
        deletePackageVersionForAuthenticatedUser: [
          "DELETE /user/packages/{package_type}/{package_name}/versions/{package_version_id}"
        ],
        deletePackageVersionForOrg: [
          "DELETE /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}"
        ],
        deletePackageVersionForUser: [
          "DELETE /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}"
        ],
        getAllPackageVersionsForAPackageOwnedByAnOrg: [
          "GET /orgs/{org}/packages/{package_type}/{package_name}/versions",
          {},
          { renamed: ["packages", "getAllPackageVersionsForPackageOwnedByOrg"] }
        ],
        getAllPackageVersionsForAPackageOwnedByTheAuthenticatedUser: [
          "GET /user/packages/{package_type}/{package_name}/versions",
          {},
          {
            renamed: [
              "packages",
              "getAllPackageVersionsForPackageOwnedByAuthenticatedUser"
            ]
          }
        ],
        getAllPackageVersionsForPackageOwnedByAuthenticatedUser: [
          "GET /user/packages/{package_type}/{package_name}/versions"
        ],
        getAllPackageVersionsForPackageOwnedByOrg: [
          "GET /orgs/{org}/packages/{package_type}/{package_name}/versions"
        ],
        getAllPackageVersionsForPackageOwnedByUser: [
          "GET /users/{username}/packages/{package_type}/{package_name}/versions"
        ],
        getPackageForAuthenticatedUser: [
          "GET /user/packages/{package_type}/{package_name}"
        ],
        getPackageForOrganization: [
          "GET /orgs/{org}/packages/{package_type}/{package_name}"
        ],
        getPackageForUser: [
          "GET /users/{username}/packages/{package_type}/{package_name}"
        ],
        getPackageVersionForAuthenticatedUser: [
          "GET /user/packages/{package_type}/{package_name}/versions/{package_version_id}"
        ],
        getPackageVersionForOrganization: [
          "GET /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}"
        ],
        getPackageVersionForUser: [
          "GET /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}"
        ],
        listDockerMigrationConflictingPackagesForAuthenticatedUser: [
          "GET /user/docker/conflicts"
        ],
        listDockerMigrationConflictingPackagesForOrganization: [
          "GET /orgs/{org}/docker/conflicts"
        ],
        listDockerMigrationConflictingPackagesForUser: [
          "GET /users/{username}/docker/conflicts"
        ],
        listPackagesForAuthenticatedUser: ["GET /user/packages"],
        listPackagesForOrganization: ["GET /orgs/{org}/packages"],
        listPackagesForUser: ["GET /users/{username}/packages"],
        restorePackageForAuthenticatedUser: [
          "POST /user/packages/{package_type}/{package_name}/restore{?token}"
        ],
        restorePackageForOrg: [
          "POST /orgs/{org}/packages/{package_type}/{package_name}/restore{?token}"
        ],
        restorePackageForUser: [
          "POST /users/{username}/packages/{package_type}/{package_name}/restore{?token}"
        ],
        restorePackageVersionForAuthenticatedUser: [
          "POST /user/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
        ],
        restorePackageVersionForOrg: [
          "POST /orgs/{org}/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
        ],
        restorePackageVersionForUser: [
          "POST /users/{username}/packages/{package_type}/{package_name}/versions/{package_version_id}/restore"
        ]
      },
      projects: {
        addCollaborator: ["PUT /projects/{project_id}/collaborators/{username}"],
        createCard: ["POST /projects/columns/{column_id}/cards"],
        createColumn: ["POST /projects/{project_id}/columns"],
        createForAuthenticatedUser: ["POST /user/projects"],
        createForOrg: ["POST /orgs/{org}/projects"],
        createForRepo: ["POST /repos/{owner}/{repo}/projects"],
        delete: ["DELETE /projects/{project_id}"],
        deleteCard: ["DELETE /projects/columns/cards/{card_id}"],
        deleteColumn: ["DELETE /projects/columns/{column_id}"],
        get: ["GET /projects/{project_id}"],
        getCard: ["GET /projects/columns/cards/{card_id}"],
        getColumn: ["GET /projects/columns/{column_id}"],
        getPermissionForUser: [
          "GET /projects/{project_id}/collaborators/{username}/permission"
        ],
        listCards: ["GET /projects/columns/{column_id}/cards"],
        listCollaborators: ["GET /projects/{project_id}/collaborators"],
        listColumns: ["GET /projects/{project_id}/columns"],
        listForOrg: ["GET /orgs/{org}/projects"],
        listForRepo: ["GET /repos/{owner}/{repo}/projects"],
        listForUser: ["GET /users/{username}/projects"],
        moveCard: ["POST /projects/columns/cards/{card_id}/moves"],
        moveColumn: ["POST /projects/columns/{column_id}/moves"],
        removeCollaborator: [
          "DELETE /projects/{project_id}/collaborators/{username}"
        ],
        update: ["PATCH /projects/{project_id}"],
        updateCard: ["PATCH /projects/columns/cards/{card_id}"],
        updateColumn: ["PATCH /projects/columns/{column_id}"]
      },
      pulls: {
        checkIfMerged: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/merge"],
        create: ["POST /repos/{owner}/{repo}/pulls"],
        createReplyForReviewComment: [
          "POST /repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies"
        ],
        createReview: ["POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews"],
        createReviewComment: [
          "POST /repos/{owner}/{repo}/pulls/{pull_number}/comments"
        ],
        deletePendingReview: [
          "DELETE /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
        ],
        deleteReviewComment: [
          "DELETE /repos/{owner}/{repo}/pulls/comments/{comment_id}"
        ],
        dismissReview: [
          "PUT /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/dismissals"
        ],
        get: ["GET /repos/{owner}/{repo}/pulls/{pull_number}"],
        getReview: [
          "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
        ],
        getReviewComment: ["GET /repos/{owner}/{repo}/pulls/comments/{comment_id}"],
        list: ["GET /repos/{owner}/{repo}/pulls"],
        listCommentsForReview: [
          "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/comments"
        ],
        listCommits: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/commits"],
        listFiles: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/files"],
        listRequestedReviewers: [
          "GET /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
        ],
        listReviewComments: [
          "GET /repos/{owner}/{repo}/pulls/{pull_number}/comments"
        ],
        listReviewCommentsForRepo: ["GET /repos/{owner}/{repo}/pulls/comments"],
        listReviews: ["GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews"],
        merge: ["PUT /repos/{owner}/{repo}/pulls/{pull_number}/merge"],
        removeRequestedReviewers: [
          "DELETE /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
        ],
        requestReviewers: [
          "POST /repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers"
        ],
        submitReview: [
          "POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}/events"
        ],
        update: ["PATCH /repos/{owner}/{repo}/pulls/{pull_number}"],
        updateBranch: [
          "PUT /repos/{owner}/{repo}/pulls/{pull_number}/update-branch"
        ],
        updateReview: [
          "PUT /repos/{owner}/{repo}/pulls/{pull_number}/reviews/{review_id}"
        ],
        updateReviewComment: [
          "PATCH /repos/{owner}/{repo}/pulls/comments/{comment_id}"
        ]
      },
      rateLimit: { get: ["GET /rate_limit"] },
      reactions: {
        createForCommitComment: [
          "POST /repos/{owner}/{repo}/comments/{comment_id}/reactions"
        ],
        createForIssue: [
          "POST /repos/{owner}/{repo}/issues/{issue_number}/reactions"
        ],
        createForIssueComment: [
          "POST /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions"
        ],
        createForPullRequestReviewComment: [
          "POST /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions"
        ],
        createForRelease: [
          "POST /repos/{owner}/{repo}/releases/{release_id}/reactions"
        ],
        createForTeamDiscussionCommentInOrg: [
          "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions"
        ],
        createForTeamDiscussionInOrg: [
          "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions"
        ],
        deleteForCommitComment: [
          "DELETE /repos/{owner}/{repo}/comments/{comment_id}/reactions/{reaction_id}"
        ],
        deleteForIssue: [
          "DELETE /repos/{owner}/{repo}/issues/{issue_number}/reactions/{reaction_id}"
        ],
        deleteForIssueComment: [
          "DELETE /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions/{reaction_id}"
        ],
        deleteForPullRequestComment: [
          "DELETE /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions/{reaction_id}"
        ],
        deleteForRelease: [
          "DELETE /repos/{owner}/{repo}/releases/{release_id}/reactions/{reaction_id}"
        ],
        deleteForTeamDiscussion: [
          "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions/{reaction_id}"
        ],
        deleteForTeamDiscussionComment: [
          "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions/{reaction_id}"
        ],
        listForCommitComment: [
          "GET /repos/{owner}/{repo}/comments/{comment_id}/reactions"
        ],
        listForIssue: ["GET /repos/{owner}/{repo}/issues/{issue_number}/reactions"],
        listForIssueComment: [
          "GET /repos/{owner}/{repo}/issues/comments/{comment_id}/reactions"
        ],
        listForPullRequestReviewComment: [
          "GET /repos/{owner}/{repo}/pulls/comments/{comment_id}/reactions"
        ],
        listForRelease: [
          "GET /repos/{owner}/{repo}/releases/{release_id}/reactions"
        ],
        listForTeamDiscussionCommentInOrg: [
          "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}/reactions"
        ],
        listForTeamDiscussionInOrg: [
          "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/reactions"
        ]
      },
      repos: {
        acceptInvitation: [
          "PATCH /user/repository_invitations/{invitation_id}",
          {},
          { renamed: ["repos", "acceptInvitationForAuthenticatedUser"] }
        ],
        acceptInvitationForAuthenticatedUser: [
          "PATCH /user/repository_invitations/{invitation_id}"
        ],
        addAppAccessRestrictions: [
          "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
          {},
          { mapToData: "apps" }
        ],
        addCollaborator: ["PUT /repos/{owner}/{repo}/collaborators/{username}"],
        addStatusCheckContexts: [
          "POST /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
          {},
          { mapToData: "contexts" }
        ],
        addTeamAccessRestrictions: [
          "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
          {},
          { mapToData: "teams" }
        ],
        addUserAccessRestrictions: [
          "POST /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
          {},
          { mapToData: "users" }
        ],
        checkAutomatedSecurityFixes: [
          "GET /repos/{owner}/{repo}/automated-security-fixes"
        ],
        checkCollaborator: ["GET /repos/{owner}/{repo}/collaborators/{username}"],
        checkVulnerabilityAlerts: [
          "GET /repos/{owner}/{repo}/vulnerability-alerts"
        ],
        codeownersErrors: ["GET /repos/{owner}/{repo}/codeowners/errors"],
        compareCommits: ["GET /repos/{owner}/{repo}/compare/{base}...{head}"],
        compareCommitsWithBasehead: [
          "GET /repos/{owner}/{repo}/compare/{basehead}"
        ],
        createAutolink: ["POST /repos/{owner}/{repo}/autolinks"],
        createCommitComment: [
          "POST /repos/{owner}/{repo}/commits/{commit_sha}/comments"
        ],
        createCommitSignatureProtection: [
          "POST /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
        ],
        createCommitStatus: ["POST /repos/{owner}/{repo}/statuses/{sha}"],
        createDeployKey: ["POST /repos/{owner}/{repo}/keys"],
        createDeployment: ["POST /repos/{owner}/{repo}/deployments"],
        createDeploymentBranchPolicy: [
          "POST /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies"
        ],
        createDeploymentProtectionRule: [
          "POST /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules"
        ],
        createDeploymentStatus: [
          "POST /repos/{owner}/{repo}/deployments/{deployment_id}/statuses"
        ],
        createDispatchEvent: ["POST /repos/{owner}/{repo}/dispatches"],
        createForAuthenticatedUser: ["POST /user/repos"],
        createFork: ["POST /repos/{owner}/{repo}/forks"],
        createInOrg: ["POST /orgs/{org}/repos"],
        createOrUpdateEnvironment: [
          "PUT /repos/{owner}/{repo}/environments/{environment_name}"
        ],
        createOrUpdateFileContents: ["PUT /repos/{owner}/{repo}/contents/{path}"],
        createOrgRuleset: ["POST /orgs/{org}/rulesets"],
        createPagesDeployment: ["POST /repos/{owner}/{repo}/pages/deployment"],
        createPagesSite: ["POST /repos/{owner}/{repo}/pages"],
        createRelease: ["POST /repos/{owner}/{repo}/releases"],
        createRepoRuleset: ["POST /repos/{owner}/{repo}/rulesets"],
        createTagProtection: ["POST /repos/{owner}/{repo}/tags/protection"],
        createUsingTemplate: [
          "POST /repos/{template_owner}/{template_repo}/generate"
        ],
        createWebhook: ["POST /repos/{owner}/{repo}/hooks"],
        declineInvitation: [
          "DELETE /user/repository_invitations/{invitation_id}",
          {},
          { renamed: ["repos", "declineInvitationForAuthenticatedUser"] }
        ],
        declineInvitationForAuthenticatedUser: [
          "DELETE /user/repository_invitations/{invitation_id}"
        ],
        delete: ["DELETE /repos/{owner}/{repo}"],
        deleteAccessRestrictions: [
          "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions"
        ],
        deleteAdminBranchProtection: [
          "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
        ],
        deleteAnEnvironment: [
          "DELETE /repos/{owner}/{repo}/environments/{environment_name}"
        ],
        deleteAutolink: ["DELETE /repos/{owner}/{repo}/autolinks/{autolink_id}"],
        deleteBranchProtection: [
          "DELETE /repos/{owner}/{repo}/branches/{branch}/protection"
        ],
        deleteCommitComment: ["DELETE /repos/{owner}/{repo}/comments/{comment_id}"],
        deleteCommitSignatureProtection: [
          "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
        ],
        deleteDeployKey: ["DELETE /repos/{owner}/{repo}/keys/{key_id}"],
        deleteDeployment: [
          "DELETE /repos/{owner}/{repo}/deployments/{deployment_id}"
        ],
        deleteDeploymentBranchPolicy: [
          "DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
        ],
        deleteFile: ["DELETE /repos/{owner}/{repo}/contents/{path}"],
        deleteInvitation: [
          "DELETE /repos/{owner}/{repo}/invitations/{invitation_id}"
        ],
        deleteOrgRuleset: ["DELETE /orgs/{org}/rulesets/{ruleset_id}"],
        deletePagesSite: ["DELETE /repos/{owner}/{repo}/pages"],
        deletePullRequestReviewProtection: [
          "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
        ],
        deleteRelease: ["DELETE /repos/{owner}/{repo}/releases/{release_id}"],
        deleteReleaseAsset: [
          "DELETE /repos/{owner}/{repo}/releases/assets/{asset_id}"
        ],
        deleteRepoRuleset: ["DELETE /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
        deleteTagProtection: [
          "DELETE /repos/{owner}/{repo}/tags/protection/{tag_protection_id}"
        ],
        deleteWebhook: ["DELETE /repos/{owner}/{repo}/hooks/{hook_id}"],
        disableAutomatedSecurityFixes: [
          "DELETE /repos/{owner}/{repo}/automated-security-fixes"
        ],
        disableDeploymentProtectionRule: [
          "DELETE /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/{protection_rule_id}"
        ],
        disablePrivateVulnerabilityReporting: [
          "DELETE /repos/{owner}/{repo}/private-vulnerability-reporting"
        ],
        disableVulnerabilityAlerts: [
          "DELETE /repos/{owner}/{repo}/vulnerability-alerts"
        ],
        downloadArchive: [
          "GET /repos/{owner}/{repo}/zipball/{ref}",
          {},
          { renamed: ["repos", "downloadZipballArchive"] }
        ],
        downloadTarballArchive: ["GET /repos/{owner}/{repo}/tarball/{ref}"],
        downloadZipballArchive: ["GET /repos/{owner}/{repo}/zipball/{ref}"],
        enableAutomatedSecurityFixes: [
          "PUT /repos/{owner}/{repo}/automated-security-fixes"
        ],
        enablePrivateVulnerabilityReporting: [
          "PUT /repos/{owner}/{repo}/private-vulnerability-reporting"
        ],
        enableVulnerabilityAlerts: [
          "PUT /repos/{owner}/{repo}/vulnerability-alerts"
        ],
        generateReleaseNotes: [
          "POST /repos/{owner}/{repo}/releases/generate-notes"
        ],
        get: ["GET /repos/{owner}/{repo}"],
        getAccessRestrictions: [
          "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions"
        ],
        getAdminBranchProtection: [
          "GET /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
        ],
        getAllDeploymentProtectionRules: [
          "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules"
        ],
        getAllEnvironments: ["GET /repos/{owner}/{repo}/environments"],
        getAllStatusCheckContexts: [
          "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts"
        ],
        getAllTopics: ["GET /repos/{owner}/{repo}/topics"],
        getAppsWithAccessToProtectedBranch: [
          "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps"
        ],
        getAutolink: ["GET /repos/{owner}/{repo}/autolinks/{autolink_id}"],
        getBranch: ["GET /repos/{owner}/{repo}/branches/{branch}"],
        getBranchProtection: [
          "GET /repos/{owner}/{repo}/branches/{branch}/protection"
        ],
        getBranchRules: ["GET /repos/{owner}/{repo}/rules/branches/{branch}"],
        getClones: ["GET /repos/{owner}/{repo}/traffic/clones"],
        getCodeFrequencyStats: ["GET /repos/{owner}/{repo}/stats/code_frequency"],
        getCollaboratorPermissionLevel: [
          "GET /repos/{owner}/{repo}/collaborators/{username}/permission"
        ],
        getCombinedStatusForRef: ["GET /repos/{owner}/{repo}/commits/{ref}/status"],
        getCommit: ["GET /repos/{owner}/{repo}/commits/{ref}"],
        getCommitActivityStats: ["GET /repos/{owner}/{repo}/stats/commit_activity"],
        getCommitComment: ["GET /repos/{owner}/{repo}/comments/{comment_id}"],
        getCommitSignatureProtection: [
          "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_signatures"
        ],
        getCommunityProfileMetrics: ["GET /repos/{owner}/{repo}/community/profile"],
        getContent: ["GET /repos/{owner}/{repo}/contents/{path}"],
        getContributorsStats: ["GET /repos/{owner}/{repo}/stats/contributors"],
        getCustomDeploymentProtectionRule: [
          "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/{protection_rule_id}"
        ],
        getDeployKey: ["GET /repos/{owner}/{repo}/keys/{key_id}"],
        getDeployment: ["GET /repos/{owner}/{repo}/deployments/{deployment_id}"],
        getDeploymentBranchPolicy: [
          "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
        ],
        getDeploymentStatus: [
          "GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses/{status_id}"
        ],
        getEnvironment: [
          "GET /repos/{owner}/{repo}/environments/{environment_name}"
        ],
        getLatestPagesBuild: ["GET /repos/{owner}/{repo}/pages/builds/latest"],
        getLatestRelease: ["GET /repos/{owner}/{repo}/releases/latest"],
        getOrgRuleset: ["GET /orgs/{org}/rulesets/{ruleset_id}"],
        getOrgRulesets: ["GET /orgs/{org}/rulesets"],
        getPages: ["GET /repos/{owner}/{repo}/pages"],
        getPagesBuild: ["GET /repos/{owner}/{repo}/pages/builds/{build_id}"],
        getPagesHealthCheck: ["GET /repos/{owner}/{repo}/pages/health"],
        getParticipationStats: ["GET /repos/{owner}/{repo}/stats/participation"],
        getPullRequestReviewProtection: [
          "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
        ],
        getPunchCardStats: ["GET /repos/{owner}/{repo}/stats/punch_card"],
        getReadme: ["GET /repos/{owner}/{repo}/readme"],
        getReadmeInDirectory: ["GET /repos/{owner}/{repo}/readme/{dir}"],
        getRelease: ["GET /repos/{owner}/{repo}/releases/{release_id}"],
        getReleaseAsset: ["GET /repos/{owner}/{repo}/releases/assets/{asset_id}"],
        getReleaseByTag: ["GET /repos/{owner}/{repo}/releases/tags/{tag}"],
        getRepoRuleset: ["GET /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
        getRepoRulesets: ["GET /repos/{owner}/{repo}/rulesets"],
        getStatusChecksProtection: [
          "GET /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
        ],
        getTeamsWithAccessToProtectedBranch: [
          "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams"
        ],
        getTopPaths: ["GET /repos/{owner}/{repo}/traffic/popular/paths"],
        getTopReferrers: ["GET /repos/{owner}/{repo}/traffic/popular/referrers"],
        getUsersWithAccessToProtectedBranch: [
          "GET /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users"
        ],
        getViews: ["GET /repos/{owner}/{repo}/traffic/views"],
        getWebhook: ["GET /repos/{owner}/{repo}/hooks/{hook_id}"],
        getWebhookConfigForRepo: [
          "GET /repos/{owner}/{repo}/hooks/{hook_id}/config"
        ],
        getWebhookDelivery: [
          "GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries/{delivery_id}"
        ],
        listActivities: ["GET /repos/{owner}/{repo}/activity"],
        listAutolinks: ["GET /repos/{owner}/{repo}/autolinks"],
        listBranches: ["GET /repos/{owner}/{repo}/branches"],
        listBranchesForHeadCommit: [
          "GET /repos/{owner}/{repo}/commits/{commit_sha}/branches-where-head"
        ],
        listCollaborators: ["GET /repos/{owner}/{repo}/collaborators"],
        listCommentsForCommit: [
          "GET /repos/{owner}/{repo}/commits/{commit_sha}/comments"
        ],
        listCommitCommentsForRepo: ["GET /repos/{owner}/{repo}/comments"],
        listCommitStatusesForRef: [
          "GET /repos/{owner}/{repo}/commits/{ref}/statuses"
        ],
        listCommits: ["GET /repos/{owner}/{repo}/commits"],
        listContributors: ["GET /repos/{owner}/{repo}/contributors"],
        listCustomDeploymentRuleIntegrations: [
          "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment_protection_rules/apps"
        ],
        listDeployKeys: ["GET /repos/{owner}/{repo}/keys"],
        listDeploymentBranchPolicies: [
          "GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies"
        ],
        listDeploymentStatuses: [
          "GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses"
        ],
        listDeployments: ["GET /repos/{owner}/{repo}/deployments"],
        listForAuthenticatedUser: ["GET /user/repos"],
        listForOrg: ["GET /orgs/{org}/repos"],
        listForUser: ["GET /users/{username}/repos"],
        listForks: ["GET /repos/{owner}/{repo}/forks"],
        listInvitations: ["GET /repos/{owner}/{repo}/invitations"],
        listInvitationsForAuthenticatedUser: ["GET /user/repository_invitations"],
        listLanguages: ["GET /repos/{owner}/{repo}/languages"],
        listPagesBuilds: ["GET /repos/{owner}/{repo}/pages/builds"],
        listPublic: ["GET /repositories"],
        listPullRequestsAssociatedWithCommit: [
          "GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls"
        ],
        listReleaseAssets: [
          "GET /repos/{owner}/{repo}/releases/{release_id}/assets"
        ],
        listReleases: ["GET /repos/{owner}/{repo}/releases"],
        listTagProtection: ["GET /repos/{owner}/{repo}/tags/protection"],
        listTags: ["GET /repos/{owner}/{repo}/tags"],
        listTeams: ["GET /repos/{owner}/{repo}/teams"],
        listWebhookDeliveries: [
          "GET /repos/{owner}/{repo}/hooks/{hook_id}/deliveries"
        ],
        listWebhooks: ["GET /repos/{owner}/{repo}/hooks"],
        merge: ["POST /repos/{owner}/{repo}/merges"],
        mergeUpstream: ["POST /repos/{owner}/{repo}/merge-upstream"],
        pingWebhook: ["POST /repos/{owner}/{repo}/hooks/{hook_id}/pings"],
        redeliverWebhookDelivery: [
          "POST /repos/{owner}/{repo}/hooks/{hook_id}/deliveries/{delivery_id}/attempts"
        ],
        removeAppAccessRestrictions: [
          "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
          {},
          { mapToData: "apps" }
        ],
        removeCollaborator: [
          "DELETE /repos/{owner}/{repo}/collaborators/{username}"
        ],
        removeStatusCheckContexts: [
          "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
          {},
          { mapToData: "contexts" }
        ],
        removeStatusCheckProtection: [
          "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
        ],
        removeTeamAccessRestrictions: [
          "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
          {},
          { mapToData: "teams" }
        ],
        removeUserAccessRestrictions: [
          "DELETE /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
          {},
          { mapToData: "users" }
        ],
        renameBranch: ["POST /repos/{owner}/{repo}/branches/{branch}/rename"],
        replaceAllTopics: ["PUT /repos/{owner}/{repo}/topics"],
        requestPagesBuild: ["POST /repos/{owner}/{repo}/pages/builds"],
        setAdminBranchProtection: [
          "POST /repos/{owner}/{repo}/branches/{branch}/protection/enforce_admins"
        ],
        setAppAccessRestrictions: [
          "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/apps",
          {},
          { mapToData: "apps" }
        ],
        setStatusCheckContexts: [
          "PUT /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks/contexts",
          {},
          { mapToData: "contexts" }
        ],
        setTeamAccessRestrictions: [
          "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/teams",
          {},
          { mapToData: "teams" }
        ],
        setUserAccessRestrictions: [
          "PUT /repos/{owner}/{repo}/branches/{branch}/protection/restrictions/users",
          {},
          { mapToData: "users" }
        ],
        testPushWebhook: ["POST /repos/{owner}/{repo}/hooks/{hook_id}/tests"],
        transfer: ["POST /repos/{owner}/{repo}/transfer"],
        update: ["PATCH /repos/{owner}/{repo}"],
        updateBranchProtection: [
          "PUT /repos/{owner}/{repo}/branches/{branch}/protection"
        ],
        updateCommitComment: ["PATCH /repos/{owner}/{repo}/comments/{comment_id}"],
        updateDeploymentBranchPolicy: [
          "PUT /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies/{branch_policy_id}"
        ],
        updateInformationAboutPagesSite: ["PUT /repos/{owner}/{repo}/pages"],
        updateInvitation: [
          "PATCH /repos/{owner}/{repo}/invitations/{invitation_id}"
        ],
        updateOrgRuleset: ["PUT /orgs/{org}/rulesets/{ruleset_id}"],
        updatePullRequestReviewProtection: [
          "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_pull_request_reviews"
        ],
        updateRelease: ["PATCH /repos/{owner}/{repo}/releases/{release_id}"],
        updateReleaseAsset: [
          "PATCH /repos/{owner}/{repo}/releases/assets/{asset_id}"
        ],
        updateRepoRuleset: ["PUT /repos/{owner}/{repo}/rulesets/{ruleset_id}"],
        updateStatusCheckPotection: [
          "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks",
          {},
          { renamed: ["repos", "updateStatusCheckProtection"] }
        ],
        updateStatusCheckProtection: [
          "PATCH /repos/{owner}/{repo}/branches/{branch}/protection/required_status_checks"
        ],
        updateWebhook: ["PATCH /repos/{owner}/{repo}/hooks/{hook_id}"],
        updateWebhookConfigForRepo: [
          "PATCH /repos/{owner}/{repo}/hooks/{hook_id}/config"
        ],
        uploadReleaseAsset: [
          "POST /repos/{owner}/{repo}/releases/{release_id}/assets{?name,label}",
          { baseUrl: "https://uploads.github.com" }
        ]
      },
      search: {
        code: ["GET /search/code"],
        commits: ["GET /search/commits"],
        issuesAndPullRequests: ["GET /search/issues"],
        labels: ["GET /search/labels"],
        repos: ["GET /search/repositories"],
        topics: ["GET /search/topics"],
        users: ["GET /search/users"]
      },
      secretScanning: {
        getAlert: [
          "GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}"
        ],
        listAlertsForEnterprise: [
          "GET /enterprises/{enterprise}/secret-scanning/alerts"
        ],
        listAlertsForOrg: ["GET /orgs/{org}/secret-scanning/alerts"],
        listAlertsForRepo: ["GET /repos/{owner}/{repo}/secret-scanning/alerts"],
        listLocationsForAlert: [
          "GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations"
        ],
        updateAlert: [
          "PATCH /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}"
        ]
      },
      securityAdvisories: {
        createPrivateVulnerabilityReport: [
          "POST /repos/{owner}/{repo}/security-advisories/reports"
        ],
        createRepositoryAdvisory: [
          "POST /repos/{owner}/{repo}/security-advisories"
        ],
        createRepositoryAdvisoryCveRequest: [
          "POST /repos/{owner}/{repo}/security-advisories/{ghsa_id}/cve"
        ],
        getGlobalAdvisory: ["GET /advisories/{ghsa_id}"],
        getRepositoryAdvisory: [
          "GET /repos/{owner}/{repo}/security-advisories/{ghsa_id}"
        ],
        listGlobalAdvisories: ["GET /advisories"],
        listOrgRepositoryAdvisories: ["GET /orgs/{org}/security-advisories"],
        listRepositoryAdvisories: ["GET /repos/{owner}/{repo}/security-advisories"],
        updateRepositoryAdvisory: [
          "PATCH /repos/{owner}/{repo}/security-advisories/{ghsa_id}"
        ]
      },
      teams: {
        addOrUpdateMembershipForUserInOrg: [
          "PUT /orgs/{org}/teams/{team_slug}/memberships/{username}"
        ],
        addOrUpdateProjectPermissionsInOrg: [
          "PUT /orgs/{org}/teams/{team_slug}/projects/{project_id}"
        ],
        addOrUpdateRepoPermissionsInOrg: [
          "PUT /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
        ],
        checkPermissionsForProjectInOrg: [
          "GET /orgs/{org}/teams/{team_slug}/projects/{project_id}"
        ],
        checkPermissionsForRepoInOrg: [
          "GET /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
        ],
        create: ["POST /orgs/{org}/teams"],
        createDiscussionCommentInOrg: [
          "POST /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments"
        ],
        createDiscussionInOrg: ["POST /orgs/{org}/teams/{team_slug}/discussions"],
        deleteDiscussionCommentInOrg: [
          "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
        ],
        deleteDiscussionInOrg: [
          "DELETE /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
        ],
        deleteInOrg: ["DELETE /orgs/{org}/teams/{team_slug}"],
        getByName: ["GET /orgs/{org}/teams/{team_slug}"],
        getDiscussionCommentInOrg: [
          "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
        ],
        getDiscussionInOrg: [
          "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
        ],
        getMembershipForUserInOrg: [
          "GET /orgs/{org}/teams/{team_slug}/memberships/{username}"
        ],
        list: ["GET /orgs/{org}/teams"],
        listChildInOrg: ["GET /orgs/{org}/teams/{team_slug}/teams"],
        listDiscussionCommentsInOrg: [
          "GET /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments"
        ],
        listDiscussionsInOrg: ["GET /orgs/{org}/teams/{team_slug}/discussions"],
        listForAuthenticatedUser: ["GET /user/teams"],
        listMembersInOrg: ["GET /orgs/{org}/teams/{team_slug}/members"],
        listPendingInvitationsInOrg: [
          "GET /orgs/{org}/teams/{team_slug}/invitations"
        ],
        listProjectsInOrg: ["GET /orgs/{org}/teams/{team_slug}/projects"],
        listReposInOrg: ["GET /orgs/{org}/teams/{team_slug}/repos"],
        removeMembershipForUserInOrg: [
          "DELETE /orgs/{org}/teams/{team_slug}/memberships/{username}"
        ],
        removeProjectInOrg: [
          "DELETE /orgs/{org}/teams/{team_slug}/projects/{project_id}"
        ],
        removeRepoInOrg: [
          "DELETE /orgs/{org}/teams/{team_slug}/repos/{owner}/{repo}"
        ],
        updateDiscussionCommentInOrg: [
          "PATCH /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments/{comment_number}"
        ],
        updateDiscussionInOrg: [
          "PATCH /orgs/{org}/teams/{team_slug}/discussions/{discussion_number}"
        ],
        updateInOrg: ["PATCH /orgs/{org}/teams/{team_slug}"]
      },
      users: {
        addEmailForAuthenticated: [
          "POST /user/emails",
          {},
          { renamed: ["users", "addEmailForAuthenticatedUser"] }
        ],
        addEmailForAuthenticatedUser: ["POST /user/emails"],
        addSocialAccountForAuthenticatedUser: ["POST /user/social_accounts"],
        block: ["PUT /user/blocks/{username}"],
        checkBlocked: ["GET /user/blocks/{username}"],
        checkFollowingForUser: ["GET /users/{username}/following/{target_user}"],
        checkPersonIsFollowedByAuthenticated: ["GET /user/following/{username}"],
        createGpgKeyForAuthenticated: [
          "POST /user/gpg_keys",
          {},
          { renamed: ["users", "createGpgKeyForAuthenticatedUser"] }
        ],
        createGpgKeyForAuthenticatedUser: ["POST /user/gpg_keys"],
        createPublicSshKeyForAuthenticated: [
          "POST /user/keys",
          {},
          { renamed: ["users", "createPublicSshKeyForAuthenticatedUser"] }
        ],
        createPublicSshKeyForAuthenticatedUser: ["POST /user/keys"],
        createSshSigningKeyForAuthenticatedUser: ["POST /user/ssh_signing_keys"],
        deleteEmailForAuthenticated: [
          "DELETE /user/emails",
          {},
          { renamed: ["users", "deleteEmailForAuthenticatedUser"] }
        ],
        deleteEmailForAuthenticatedUser: ["DELETE /user/emails"],
        deleteGpgKeyForAuthenticated: [
          "DELETE /user/gpg_keys/{gpg_key_id}",
          {},
          { renamed: ["users", "deleteGpgKeyForAuthenticatedUser"] }
        ],
        deleteGpgKeyForAuthenticatedUser: ["DELETE /user/gpg_keys/{gpg_key_id}"],
        deletePublicSshKeyForAuthenticated: [
          "DELETE /user/keys/{key_id}",
          {},
          { renamed: ["users", "deletePublicSshKeyForAuthenticatedUser"] }
        ],
        deletePublicSshKeyForAuthenticatedUser: ["DELETE /user/keys/{key_id}"],
        deleteSocialAccountForAuthenticatedUser: ["DELETE /user/social_accounts"],
        deleteSshSigningKeyForAuthenticatedUser: [
          "DELETE /user/ssh_signing_keys/{ssh_signing_key_id}"
        ],
        follow: ["PUT /user/following/{username}"],
        getAuthenticated: ["GET /user"],
        getByUsername: ["GET /users/{username}"],
        getContextForUser: ["GET /users/{username}/hovercard"],
        getGpgKeyForAuthenticated: [
          "GET /user/gpg_keys/{gpg_key_id}",
          {},
          { renamed: ["users", "getGpgKeyForAuthenticatedUser"] }
        ],
        getGpgKeyForAuthenticatedUser: ["GET /user/gpg_keys/{gpg_key_id}"],
        getPublicSshKeyForAuthenticated: [
          "GET /user/keys/{key_id}",
          {},
          { renamed: ["users", "getPublicSshKeyForAuthenticatedUser"] }
        ],
        getPublicSshKeyForAuthenticatedUser: ["GET /user/keys/{key_id}"],
        getSshSigningKeyForAuthenticatedUser: [
          "GET /user/ssh_signing_keys/{ssh_signing_key_id}"
        ],
        list: ["GET /users"],
        listBlockedByAuthenticated: [
          "GET /user/blocks",
          {},
          { renamed: ["users", "listBlockedByAuthenticatedUser"] }
        ],
        listBlockedByAuthenticatedUser: ["GET /user/blocks"],
        listEmailsForAuthenticated: [
          "GET /user/emails",
          {},
          { renamed: ["users", "listEmailsForAuthenticatedUser"] }
        ],
        listEmailsForAuthenticatedUser: ["GET /user/emails"],
        listFollowedByAuthenticated: [
          "GET /user/following",
          {},
          { renamed: ["users", "listFollowedByAuthenticatedUser"] }
        ],
        listFollowedByAuthenticatedUser: ["GET /user/following"],
        listFollowersForAuthenticatedUser: ["GET /user/followers"],
        listFollowersForUser: ["GET /users/{username}/followers"],
        listFollowingForUser: ["GET /users/{username}/following"],
        listGpgKeysForAuthenticated: [
          "GET /user/gpg_keys",
          {},
          { renamed: ["users", "listGpgKeysForAuthenticatedUser"] }
        ],
        listGpgKeysForAuthenticatedUser: ["GET /user/gpg_keys"],
        listGpgKeysForUser: ["GET /users/{username}/gpg_keys"],
        listPublicEmailsForAuthenticated: [
          "GET /user/public_emails",
          {},
          { renamed: ["users", "listPublicEmailsForAuthenticatedUser"] }
        ],
        listPublicEmailsForAuthenticatedUser: ["GET /user/public_emails"],
        listPublicKeysForUser: ["GET /users/{username}/keys"],
        listPublicSshKeysForAuthenticated: [
          "GET /user/keys",
          {},
          { renamed: ["users", "listPublicSshKeysForAuthenticatedUser"] }
        ],
        listPublicSshKeysForAuthenticatedUser: ["GET /user/keys"],
        listSocialAccountsForAuthenticatedUser: ["GET /user/social_accounts"],
        listSocialAccountsForUser: ["GET /users/{username}/social_accounts"],
        listSshSigningKeysForAuthenticatedUser: ["GET /user/ssh_signing_keys"],
        listSshSigningKeysForUser: ["GET /users/{username}/ssh_signing_keys"],
        setPrimaryEmailVisibilityForAuthenticated: [
          "PATCH /user/email/visibility",
          {},
          { renamed: ["users", "setPrimaryEmailVisibilityForAuthenticatedUser"] }
        ],
        setPrimaryEmailVisibilityForAuthenticatedUser: [
          "PATCH /user/email/visibility"
        ],
        unblock: ["DELETE /user/blocks/{username}"],
        unfollow: ["DELETE /user/following/{username}"],
        updateAuthenticated: ["PATCH /user"]
      }
    };
    var endpoints_default = Endpoints;
    var endpointMethodsMap = /* @__PURE__ */ new Map();
    for (const [scope, endpoints] of Object.entries(endpoints_default)) {
      for (const [methodName, endpoint] of Object.entries(endpoints)) {
        const [route, defaults, decorations] = endpoint;
        const [method, url] = route.split(/ /);
        const endpointDefaults = Object.assign(
          {
            method,
            url
          },
          defaults
        );
        if (!endpointMethodsMap.has(scope)) {
          endpointMethodsMap.set(scope, /* @__PURE__ */ new Map());
        }
        endpointMethodsMap.get(scope).set(methodName, {
          scope,
          methodName,
          endpointDefaults,
          decorations
        });
      }
    }
    var handler = {
      get({ octokit, scope, cache }, methodName) {
        if (cache[methodName]) {
          return cache[methodName];
        }
        const { decorations, endpointDefaults } = endpointMethodsMap.get(scope).get(methodName);
        if (decorations) {
          cache[methodName] = decorate(
            octokit,
            scope,
            methodName,
            endpointDefaults,
            decorations
          );
        } else {
          cache[methodName] = octokit.request.defaults(endpointDefaults);
        }
        return cache[methodName];
      }
    };
    function endpointsToMethods(octokit) {
      const newMethods = {};
      for (const scope of endpointMethodsMap.keys()) {
        newMethods[scope] = new Proxy({ octokit, scope, cache: {} }, handler);
      }
      return newMethods;
    }
    function decorate(octokit, scope, methodName, defaults, decorations) {
      const requestWithDefaults = octokit.request.defaults(defaults);
      function withDecorations(...args) {
        let options = requestWithDefaults.endpoint.merge(...args);
        if (decorations.mapToData) {
          options = Object.assign({}, options, {
            data: options[decorations.mapToData],
            [decorations.mapToData]: void 0
          });
          return requestWithDefaults(options);
        }
        if (decorations.renamed) {
          const [newScope, newMethodName] = decorations.renamed;
          octokit.log.warn(
            `octokit.${scope}.${methodName}() has been renamed to octokit.${newScope}.${newMethodName}()`
          );
        }
        if (decorations.deprecated) {
          octokit.log.warn(decorations.deprecated);
        }
        if (decorations.renamedParameters) {
          const options2 = requestWithDefaults.endpoint.merge(...args);
          for (const [name, alias] of Object.entries(
            decorations.renamedParameters
          )) {
            if (name in options2) {
              octokit.log.warn(
                `"${name}" parameter is deprecated for "octokit.${scope}.${methodName}()". Use "${alias}" instead`
              );
              if (!(alias in options2)) {
                options2[alias] = options2[name];
              }
              delete options2[name];
            }
          }
          return requestWithDefaults(options2);
        }
        return requestWithDefaults(...args);
      }
      return Object.assign(withDecorations, requestWithDefaults);
    }
    function restEndpointMethods(octokit) {
      const api = endpointsToMethods(octokit);
      return {
        rest: api
      };
    }
    restEndpointMethods.VERSION = VERSION;
    function legacyRestEndpointMethods(octokit) {
      const api = endpointsToMethods(octokit);
      return {
        ...api,
        rest: api
      };
    }
    legacyRestEndpointMethods.VERSION = VERSION;
  }
});

// node_modules/bottleneck/light.js
var require_light = __commonJS({
  "node_modules/bottleneck/light.js"(exports2, module2) {
    (function(global2, factory) {
      typeof exports2 === "object" && typeof module2 !== "undefined" ? module2.exports = factory() : typeof define === "function" && define.amd ? define(factory) : global2.Bottleneck = factory();
    })(exports2, function() {
      "use strict";
      var commonjsGlobal = typeof globalThis !== "undefined" ? globalThis : typeof window !== "undefined" ? window : typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : {};
      function getCjsExportFromNamespace(n) {
        return n && n["default"] || n;
      }
      var load = function(received, defaults, onto = {}) {
        var k, ref, v;
        for (k in defaults) {
          v = defaults[k];
          onto[k] = (ref = received[k]) != null ? ref : v;
        }
        return onto;
      };
      var overwrite = function(received, defaults, onto = {}) {
        var k, v;
        for (k in received) {
          v = received[k];
          if (defaults[k] !== void 0) {
            onto[k] = v;
          }
        }
        return onto;
      };
      var parser = {
        load,
        overwrite
      };
      var DLList;
      DLList = class DLList {
        constructor(incr, decr) {
          this.incr = incr;
          this.decr = decr;
          this._first = null;
          this._last = null;
          this.length = 0;
        }
        push(value) {
          var node;
          this.length++;
          if (typeof this.incr === "function") {
            this.incr();
          }
          node = {
            value,
            prev: this._last,
            next: null
          };
          if (this._last != null) {
            this._last.next = node;
            this._last = node;
          } else {
            this._first = this._last = node;
          }
          return void 0;
        }
        shift() {
          var value;
          if (this._first == null) {
            return;
          } else {
            this.length--;
            if (typeof this.decr === "function") {
              this.decr();
            }
          }
          value = this._first.value;
          if ((this._first = this._first.next) != null) {
            this._first.prev = null;
          } else {
            this._last = null;
          }
          return value;
        }
        first() {
          if (this._first != null) {
            return this._first.value;
          }
        }
        getArray() {
          var node, ref, results;
          node = this._first;
          results = [];
          while (node != null) {
            results.push((ref = node, node = node.next, ref.value));
          }
          return results;
        }
        forEachShift(cb) {
          var node;
          node = this.shift();
          while (node != null) {
            cb(node), node = this.shift();
          }
          return void 0;
        }
        debug() {
          var node, ref, ref1, ref2, results;
          node = this._first;
          results = [];
          while (node != null) {
            results.push((ref = node, node = node.next, {
              value: ref.value,
              prev: (ref1 = ref.prev) != null ? ref1.value : void 0,
              next: (ref2 = ref.next) != null ? ref2.value : void 0
            }));
          }
          return results;
        }
      };
      var DLList_1 = DLList;
      var Events;
      Events = class Events {
        constructor(instance) {
          this.instance = instance;
          this._events = {};
          if (this.instance.on != null || this.instance.once != null || this.instance.removeAllListeners != null) {
            throw new Error("An Emitter already exists for this object");
          }
          this.instance.on = (name, cb) => {
            return this._addListener(name, "many", cb);
          };
          this.instance.once = (name, cb) => {
            return this._addListener(name, "once", cb);
          };
          this.instance.removeAllListeners = (name = null) => {
            if (name != null) {
              return delete this._events[name];
            } else {
              return this._events = {};
            }
          };
        }
        _addListener(name, status, cb) {
          var base;
          if ((base = this._events)[name] == null) {
            base[name] = [];
          }
          this._events[name].push({ cb, status });
          return this.instance;
        }
        listenerCount(name) {
          if (this._events[name] != null) {
            return this._events[name].length;
          } else {
            return 0;
          }
        }
        async trigger(name, ...args) {
          var e, promises;
          try {
            if (name !== "debug") {
              this.trigger("debug", `Event triggered: ${name}`, args);
            }
            if (this._events[name] == null) {
              return;
            }
            this._events[name] = this._events[name].filter(function(listener) {
              return listener.status !== "none";
            });
            promises = this._events[name].map(async (listener) => {
              var e2, returned;
              if (listener.status === "none") {
                return;
              }
              if (listener.status === "once") {
                listener.status = "none";
              }
              try {
                returned = typeof listener.cb === "function" ? listener.cb(...args) : void 0;
                if (typeof (returned != null ? returned.then : void 0) === "function") {
                  return await returned;
                } else {
                  return returned;
                }
              } catch (error) {
                e2 = error;
                {
                  this.trigger("error", e2);
                }
                return null;
              }
            });
            return (await Promise.all(promises)).find(function(x) {
              return x != null;
            });
          } catch (error) {
            e = error;
            {
              this.trigger("error", e);
            }
            return null;
          }
        }
      };
      var Events_1 = Events;
      var DLList$1, Events$1, Queues;
      DLList$1 = DLList_1;
      Events$1 = Events_1;
      Queues = class Queues {
        constructor(num_priorities) {
          var i;
          this.Events = new Events$1(this);
          this._length = 0;
          this._lists = function() {
            var j, ref, results;
            results = [];
            for (i = j = 1, ref = num_priorities; 1 <= ref ? j <= ref : j >= ref; i = 1 <= ref ? ++j : --j) {
              results.push(new DLList$1(() => {
                return this.incr();
              }, () => {
                return this.decr();
              }));
            }
            return results;
          }.call(this);
        }
        incr() {
          if (this._length++ === 0) {
            return this.Events.trigger("leftzero");
          }
        }
        decr() {
          if (--this._length === 0) {
            return this.Events.trigger("zero");
          }
        }
        push(job) {
          return this._lists[job.options.priority].push(job);
        }
        queued(priority) {
          if (priority != null) {
            return this._lists[priority].length;
          } else {
            return this._length;
          }
        }
        shiftAll(fn) {
          return this._lists.forEach(function(list) {
            return list.forEachShift(fn);
          });
        }
        getFirst(arr = this._lists) {
          var j, len, list;
          for (j = 0, len = arr.length; j < len; j++) {
            list = arr[j];
            if (list.length > 0) {
              return list;
            }
          }
          return [];
        }
        shiftLastFrom(priority) {
          return this.getFirst(this._lists.slice(priority).reverse()).shift();
        }
      };
      var Queues_1 = Queues;
      var BottleneckError;
      BottleneckError = class BottleneckError extends Error {
      };
      var BottleneckError_1 = BottleneckError;
      var BottleneckError$1, DEFAULT_PRIORITY, Job, NUM_PRIORITIES, parser$1;
      NUM_PRIORITIES = 10;
      DEFAULT_PRIORITY = 5;
      parser$1 = parser;
      BottleneckError$1 = BottleneckError_1;
      Job = class Job {
        constructor(task, args, options, jobDefaults, rejectOnDrop, Events2, _states, Promise2) {
          this.task = task;
          this.args = args;
          this.rejectOnDrop = rejectOnDrop;
          this.Events = Events2;
          this._states = _states;
          this.Promise = Promise2;
          this.options = parser$1.load(options, jobDefaults);
          this.options.priority = this._sanitizePriority(this.options.priority);
          if (this.options.id === jobDefaults.id) {
            this.options.id = `${this.options.id}-${this._randomIndex()}`;
          }
          this.promise = new this.Promise((_resolve, _reject) => {
            this._resolve = _resolve;
            this._reject = _reject;
          });
          this.retryCount = 0;
        }
        _sanitizePriority(priority) {
          var sProperty;
          sProperty = ~~priority !== priority ? DEFAULT_PRIORITY : priority;
          if (sProperty < 0) {
            return 0;
          } else if (sProperty > NUM_PRIORITIES - 1) {
            return NUM_PRIORITIES - 1;
          } else {
            return sProperty;
          }
        }
        _randomIndex() {
          return Math.random().toString(36).slice(2);
        }
        doDrop({ error, message = "This job has been dropped by Bottleneck" } = {}) {
          if (this._states.remove(this.options.id)) {
            if (this.rejectOnDrop) {
              this._reject(error != null ? error : new BottleneckError$1(message));
            }
            this.Events.trigger("dropped", { args: this.args, options: this.options, task: this.task, promise: this.promise });
            return true;
          } else {
            return false;
          }
        }
        _assertStatus(expected) {
          var status;
          status = this._states.jobStatus(this.options.id);
          if (!(status === expected || expected === "DONE" && status === null)) {
            throw new BottleneckError$1(`Invalid job status ${status}, expected ${expected}. Please open an issue at https://github.com/SGrondin/bottleneck/issues`);
          }
        }
        doReceive() {
          this._states.start(this.options.id);
          return this.Events.trigger("received", { args: this.args, options: this.options });
        }
        doQueue(reachedHWM, blocked) {
          this._assertStatus("RECEIVED");
          this._states.next(this.options.id);
          return this.Events.trigger("queued", { args: this.args, options: this.options, reachedHWM, blocked });
        }
        doRun() {
          if (this.retryCount === 0) {
            this._assertStatus("QUEUED");
            this._states.next(this.options.id);
          } else {
            this._assertStatus("EXECUTING");
          }
          return this.Events.trigger("scheduled", { args: this.args, options: this.options });
        }
        async doExecute(chained, clearGlobalState, run2, free) {
          var error, eventInfo, passed;
          if (this.retryCount === 0) {
            this._assertStatus("RUNNING");
            this._states.next(this.options.id);
          } else {
            this._assertStatus("EXECUTING");
          }
          eventInfo = { args: this.args, options: this.options, retryCount: this.retryCount };
          this.Events.trigger("executing", eventInfo);
          try {
            passed = await (chained != null ? chained.schedule(this.options, this.task, ...this.args) : this.task(...this.args));
            if (clearGlobalState()) {
              this.doDone(eventInfo);
              await free(this.options, eventInfo);
              this._assertStatus("DONE");
              return this._resolve(passed);
            }
          } catch (error1) {
            error = error1;
            return this._onFailure(error, eventInfo, clearGlobalState, run2, free);
          }
        }
        doExpire(clearGlobalState, run2, free) {
          var error, eventInfo;
          if (this._states.jobStatus(this.options.id === "RUNNING")) {
            this._states.next(this.options.id);
          }
          this._assertStatus("EXECUTING");
          eventInfo = { args: this.args, options: this.options, retryCount: this.retryCount };
          error = new BottleneckError$1(`This job timed out after ${this.options.expiration} ms.`);
          return this._onFailure(error, eventInfo, clearGlobalState, run2, free);
        }
        async _onFailure(error, eventInfo, clearGlobalState, run2, free) {
          var retry, retryAfter;
          if (clearGlobalState()) {
            retry = await this.Events.trigger("failed", error, eventInfo);
            if (retry != null) {
              retryAfter = ~~retry;
              this.Events.trigger("retry", `Retrying ${this.options.id} after ${retryAfter} ms`, eventInfo);
              this.retryCount++;
              return run2(retryAfter);
            } else {
              this.doDone(eventInfo);
              await free(this.options, eventInfo);
              this._assertStatus("DONE");
              return this._reject(error);
            }
          }
        }
        doDone(eventInfo) {
          this._assertStatus("EXECUTING");
          this._states.next(this.options.id);
          return this.Events.trigger("done", eventInfo);
        }
      };
      var Job_1 = Job;
      var BottleneckError$2, LocalDatastore, parser$2;
      parser$2 = parser;
      BottleneckError$2 = BottleneckError_1;
      LocalDatastore = class LocalDatastore {
        constructor(instance, storeOptions, storeInstanceOptions) {
          this.instance = instance;
          this.storeOptions = storeOptions;
          this.clientId = this.instance._randomIndex();
          parser$2.load(storeInstanceOptions, storeInstanceOptions, this);
          this._nextRequest = this._lastReservoirRefresh = this._lastReservoirIncrease = Date.now();
          this._running = 0;
          this._done = 0;
          this._unblockTime = 0;
          this.ready = this.Promise.resolve();
          this.clients = {};
          this._startHeartbeat();
        }
        _startHeartbeat() {
          var base;
          if (this.heartbeat == null && (this.storeOptions.reservoirRefreshInterval != null && this.storeOptions.reservoirRefreshAmount != null || this.storeOptions.reservoirIncreaseInterval != null && this.storeOptions.reservoirIncreaseAmount != null)) {
            return typeof (base = this.heartbeat = setInterval(() => {
              var amount, incr, maximum, now, reservoir;
              now = Date.now();
              if (this.storeOptions.reservoirRefreshInterval != null && now >= this._lastReservoirRefresh + this.storeOptions.reservoirRefreshInterval) {
                this._lastReservoirRefresh = now;
                this.storeOptions.reservoir = this.storeOptions.reservoirRefreshAmount;
                this.instance._drainAll(this.computeCapacity());
              }
              if (this.storeOptions.reservoirIncreaseInterval != null && now >= this._lastReservoirIncrease + this.storeOptions.reservoirIncreaseInterval) {
                ({
                  reservoirIncreaseAmount: amount,
                  reservoirIncreaseMaximum: maximum,
                  reservoir
                } = this.storeOptions);
                this._lastReservoirIncrease = now;
                incr = maximum != null ? Math.min(amount, maximum - reservoir) : amount;
                if (incr > 0) {
                  this.storeOptions.reservoir += incr;
                  return this.instance._drainAll(this.computeCapacity());
                }
              }
            }, this.heartbeatInterval)).unref === "function" ? base.unref() : void 0;
          } else {
            return clearInterval(this.heartbeat);
          }
        }
        async __publish__(message) {
          await this.yieldLoop();
          return this.instance.Events.trigger("message", message.toString());
        }
        async __disconnect__(flush) {
          await this.yieldLoop();
          clearInterval(this.heartbeat);
          return this.Promise.resolve();
        }
        yieldLoop(t = 0) {
          return new this.Promise(function(resolve, reject) {
            return setTimeout(resolve, t);
          });
        }
        computePenalty() {
          var ref;
          return (ref = this.storeOptions.penalty) != null ? ref : 15 * this.storeOptions.minTime || 5e3;
        }
        async __updateSettings__(options) {
          await this.yieldLoop();
          parser$2.overwrite(options, options, this.storeOptions);
          this._startHeartbeat();
          this.instance._drainAll(this.computeCapacity());
          return true;
        }
        async __running__() {
          await this.yieldLoop();
          return this._running;
        }
        async __queued__() {
          await this.yieldLoop();
          return this.instance.queued();
        }
        async __done__() {
          await this.yieldLoop();
          return this._done;
        }
        async __groupCheck__(time) {
          await this.yieldLoop();
          return this._nextRequest + this.timeout < time;
        }
        computeCapacity() {
          var maxConcurrent, reservoir;
          ({ maxConcurrent, reservoir } = this.storeOptions);
          if (maxConcurrent != null && reservoir != null) {
            return Math.min(maxConcurrent - this._running, reservoir);
          } else if (maxConcurrent != null) {
            return maxConcurrent - this._running;
          } else if (reservoir != null) {
            return reservoir;
          } else {
            return null;
          }
        }
        conditionsCheck(weight) {
          var capacity;
          capacity = this.computeCapacity();
          return capacity == null || weight <= capacity;
        }
        async __incrementReservoir__(incr) {
          var reservoir;
          await this.yieldLoop();
          reservoir = this.storeOptions.reservoir += incr;
          this.instance._drainAll(this.computeCapacity());
          return reservoir;
        }
        async __currentReservoir__() {
          await this.yieldLoop();
          return this.storeOptions.reservoir;
        }
        isBlocked(now) {
          return this._unblockTime >= now;
        }
        check(weight, now) {
          return this.conditionsCheck(weight) && this._nextRequest - now <= 0;
        }
        async __check__(weight) {
          var now;
          await this.yieldLoop();
          now = Date.now();
          return this.check(weight, now);
        }
        async __register__(index, weight, expiration) {
          var now, wait;
          await this.yieldLoop();
          now = Date.now();
          if (this.conditionsCheck(weight)) {
            this._running += weight;
            if (this.storeOptions.reservoir != null) {
              this.storeOptions.reservoir -= weight;
            }
            wait = Math.max(this._nextRequest - now, 0);
            this._nextRequest = now + wait + this.storeOptions.minTime;
            return {
              success: true,
              wait,
              reservoir: this.storeOptions.reservoir
            };
          } else {
            return {
              success: false
            };
          }
        }
        strategyIsBlock() {
          return this.storeOptions.strategy === 3;
        }
        async __submit__(queueLength, weight) {
          var blocked, now, reachedHWM;
          await this.yieldLoop();
          if (this.storeOptions.maxConcurrent != null && weight > this.storeOptions.maxConcurrent) {
            throw new BottleneckError$2(`Impossible to add a job having a weight of ${weight} to a limiter having a maxConcurrent setting of ${this.storeOptions.maxConcurrent}`);
          }
          now = Date.now();
          reachedHWM = this.storeOptions.highWater != null && queueLength === this.storeOptions.highWater && !this.check(weight, now);
          blocked = this.strategyIsBlock() && (reachedHWM || this.isBlocked(now));
          if (blocked) {
            this._unblockTime = now + this.computePenalty();
            this._nextRequest = this._unblockTime + this.storeOptions.minTime;
            this.instance._dropAllQueued();
          }
          return {
            reachedHWM,
            blocked,
            strategy: this.storeOptions.strategy
          };
        }
        async __free__(index, weight) {
          await this.yieldLoop();
          this._running -= weight;
          this._done += weight;
          this.instance._drainAll(this.computeCapacity());
          return {
            running: this._running
          };
        }
      };
      var LocalDatastore_1 = LocalDatastore;
      var BottleneckError$3, States;
      BottleneckError$3 = BottleneckError_1;
      States = class States {
        constructor(status1) {
          this.status = status1;
          this._jobs = {};
          this.counts = this.status.map(function() {
            return 0;
          });
        }
        next(id) {
          var current, next;
          current = this._jobs[id];
          next = current + 1;
          if (current != null && next < this.status.length) {
            this.counts[current]--;
            this.counts[next]++;
            return this._jobs[id]++;
          } else if (current != null) {
            this.counts[current]--;
            return delete this._jobs[id];
          }
        }
        start(id) {
          var initial;
          initial = 0;
          this._jobs[id] = initial;
          return this.counts[initial]++;
        }
        remove(id) {
          var current;
          current = this._jobs[id];
          if (current != null) {
            this.counts[current]--;
            delete this._jobs[id];
          }
          return current != null;
        }
        jobStatus(id) {
          var ref;
          return (ref = this.status[this._jobs[id]]) != null ? ref : null;
        }
        statusJobs(status) {
          var k, pos, ref, results, v;
          if (status != null) {
            pos = this.status.indexOf(status);
            if (pos < 0) {
              throw new BottleneckError$3(`status must be one of ${this.status.join(", ")}`);
            }
            ref = this._jobs;
            results = [];
            for (k in ref) {
              v = ref[k];
              if (v === pos) {
                results.push(k);
              }
            }
            return results;
          } else {
            return Object.keys(this._jobs);
          }
        }
        statusCounts() {
          return this.counts.reduce((acc, v, i) => {
            acc[this.status[i]] = v;
            return acc;
          }, {});
        }
      };
      var States_1 = States;
      var DLList$2, Sync;
      DLList$2 = DLList_1;
      Sync = class Sync {
        constructor(name, Promise2) {
          this.schedule = this.schedule.bind(this);
          this.name = name;
          this.Promise = Promise2;
          this._running = 0;
          this._queue = new DLList$2();
        }
        isEmpty() {
          return this._queue.length === 0;
        }
        async _tryToRun() {
          var args, cb, error, reject, resolve, returned, task;
          if (this._running < 1 && this._queue.length > 0) {
            this._running++;
            ({ task, args, resolve, reject } = this._queue.shift());
            cb = await async function() {
              try {
                returned = await task(...args);
                return function() {
                  return resolve(returned);
                };
              } catch (error1) {
                error = error1;
                return function() {
                  return reject(error);
                };
              }
            }();
            this._running--;
            this._tryToRun();
            return cb();
          }
        }
        schedule(task, ...args) {
          var promise, reject, resolve;
          resolve = reject = null;
          promise = new this.Promise(function(_resolve, _reject) {
            resolve = _resolve;
            return reject = _reject;
          });
          this._queue.push({ task, args, resolve, reject });
          this._tryToRun();
          return promise;
        }
      };
      var Sync_1 = Sync;
      var version2 = "2.19.5";
      var version$1 = {
        version: version2
      };
      var version$2 = /* @__PURE__ */ Object.freeze({
        version: version2,
        default: version$1
      });
      var require$$2 = () => console.log("You must import the full version of Bottleneck in order to use this feature.");
      var require$$3 = () => console.log("You must import the full version of Bottleneck in order to use this feature.");
      var require$$4 = () => console.log("You must import the full version of Bottleneck in order to use this feature.");
      var Events$2, Group, IORedisConnection$1, RedisConnection$1, Scripts$1, parser$3;
      parser$3 = parser;
      Events$2 = Events_1;
      RedisConnection$1 = require$$2;
      IORedisConnection$1 = require$$3;
      Scripts$1 = require$$4;
      Group = function() {
        class Group2 {
          constructor(limiterOptions = {}) {
            this.deleteKey = this.deleteKey.bind(this);
            this.limiterOptions = limiterOptions;
            parser$3.load(this.limiterOptions, this.defaults, this);
            this.Events = new Events$2(this);
            this.instances = {};
            this.Bottleneck = Bottleneck_1;
            this._startAutoCleanup();
            this.sharedConnection = this.connection != null;
            if (this.connection == null) {
              if (this.limiterOptions.datastore === "redis") {
                this.connection = new RedisConnection$1(Object.assign({}, this.limiterOptions, { Events: this.Events }));
              } else if (this.limiterOptions.datastore === "ioredis") {
                this.connection = new IORedisConnection$1(Object.assign({}, this.limiterOptions, { Events: this.Events }));
              }
            }
          }
          key(key = "") {
            var ref;
            return (ref = this.instances[key]) != null ? ref : (() => {
              var limiter;
              limiter = this.instances[key] = new this.Bottleneck(Object.assign(this.limiterOptions, {
                id: `${this.id}-${key}`,
                timeout: this.timeout,
                connection: this.connection
              }));
              this.Events.trigger("created", limiter, key);
              return limiter;
            })();
          }
          async deleteKey(key = "") {
            var deleted, instance;
            instance = this.instances[key];
            if (this.connection) {
              deleted = await this.connection.__runCommand__(["del", ...Scripts$1.allKeys(`${this.id}-${key}`)]);
            }
            if (instance != null) {
              delete this.instances[key];
              await instance.disconnect();
            }
            return instance != null || deleted > 0;
          }
          limiters() {
            var k, ref, results, v;
            ref = this.instances;
            results = [];
            for (k in ref) {
              v = ref[k];
              results.push({
                key: k,
                limiter: v
              });
            }
            return results;
          }
          keys() {
            return Object.keys(this.instances);
          }
          async clusterKeys() {
            var cursor, end, found, i, k, keys, len, next, start;
            if (this.connection == null) {
              return this.Promise.resolve(this.keys());
            }
            keys = [];
            cursor = null;
            start = `b_${this.id}-`.length;
            end = "_settings".length;
            while (cursor !== 0) {
              [next, found] = await this.connection.__runCommand__(["scan", cursor != null ? cursor : 0, "match", `b_${this.id}-*_settings`, "count", 1e4]);
              cursor = ~~next;
              for (i = 0, len = found.length; i < len; i++) {
                k = found[i];
                keys.push(k.slice(start, -end));
              }
            }
            return keys;
          }
          _startAutoCleanup() {
            var base;
            clearInterval(this.interval);
            return typeof (base = this.interval = setInterval(async () => {
              var e, k, ref, results, time, v;
              time = Date.now();
              ref = this.instances;
              results = [];
              for (k in ref) {
                v = ref[k];
                try {
                  if (await v._store.__groupCheck__(time)) {
                    results.push(this.deleteKey(k));
                  } else {
                    results.push(void 0);
                  }
                } catch (error) {
                  e = error;
                  results.push(v.Events.trigger("error", e));
                }
              }
              return results;
            }, this.timeout / 2)).unref === "function" ? base.unref() : void 0;
          }
          updateSettings(options = {}) {
            parser$3.overwrite(options, this.defaults, this);
            parser$3.overwrite(options, options, this.limiterOptions);
            if (options.timeout != null) {
              return this._startAutoCleanup();
            }
          }
          disconnect(flush = true) {
            var ref;
            if (!this.sharedConnection) {
              return (ref = this.connection) != null ? ref.disconnect(flush) : void 0;
            }
          }
        }
        Group2.prototype.defaults = {
          timeout: 1e3 * 60 * 5,
          connection: null,
          Promise,
          id: "group-key"
        };
        return Group2;
      }.call(commonjsGlobal);
      var Group_1 = Group;
      var Batcher, Events$3, parser$4;
      parser$4 = parser;
      Events$3 = Events_1;
      Batcher = function() {
        class Batcher2 {
          constructor(options = {}) {
            this.options = options;
            parser$4.load(this.options, this.defaults, this);
            this.Events = new Events$3(this);
            this._arr = [];
            this._resetPromise();
            this._lastFlush = Date.now();
          }
          _resetPromise() {
            return this._promise = new this.Promise((res, rej) => {
              return this._resolve = res;
            });
          }
          _flush() {
            clearTimeout(this._timeout);
            this._lastFlush = Date.now();
            this._resolve();
            this.Events.trigger("batch", this._arr);
            this._arr = [];
            return this._resetPromise();
          }
          add(data) {
            var ret;
            this._arr.push(data);
            ret = this._promise;
            if (this._arr.length === this.maxSize) {
              this._flush();
            } else if (this.maxTime != null && this._arr.length === 1) {
              this._timeout = setTimeout(() => {
                return this._flush();
              }, this.maxTime);
            }
            return ret;
          }
        }
        Batcher2.prototype.defaults = {
          maxTime: null,
          maxSize: null,
          Promise
        };
        return Batcher2;
      }.call(commonjsGlobal);
      var Batcher_1 = Batcher;
      var require$$4$1 = () => console.log("You must import the full version of Bottleneck in order to use this feature.");
      var require$$8 = getCjsExportFromNamespace(version$2);
      var Bottleneck, DEFAULT_PRIORITY$1, Events$4, Job$1, LocalDatastore$1, NUM_PRIORITIES$1, Queues$1, RedisDatastore$1, States$1, Sync$1, parser$5, splice = [].splice;
      NUM_PRIORITIES$1 = 10;
      DEFAULT_PRIORITY$1 = 5;
      parser$5 = parser;
      Queues$1 = Queues_1;
      Job$1 = Job_1;
      LocalDatastore$1 = LocalDatastore_1;
      RedisDatastore$1 = require$$4$1;
      Events$4 = Events_1;
      States$1 = States_1;
      Sync$1 = Sync_1;
      Bottleneck = function() {
        class Bottleneck2 {
          constructor(options = {}, ...invalid) {
            var storeInstanceOptions, storeOptions;
            this._addToQueue = this._addToQueue.bind(this);
            this._validateOptions(options, invalid);
            parser$5.load(options, this.instanceDefaults, this);
            this._queues = new Queues$1(NUM_PRIORITIES$1);
            this._scheduled = {};
            this._states = new States$1(["RECEIVED", "QUEUED", "RUNNING", "EXECUTING"].concat(this.trackDoneStatus ? ["DONE"] : []));
            this._limiter = null;
            this.Events = new Events$4(this);
            this._submitLock = new Sync$1("submit", this.Promise);
            this._registerLock = new Sync$1("register", this.Promise);
            storeOptions = parser$5.load(options, this.storeDefaults, {});
            this._store = function() {
              if (this.datastore === "redis" || this.datastore === "ioredis" || this.connection != null) {
                storeInstanceOptions = parser$5.load(options, this.redisStoreDefaults, {});
                return new RedisDatastore$1(this, storeOptions, storeInstanceOptions);
              } else if (this.datastore === "local") {
                storeInstanceOptions = parser$5.load(options, this.localStoreDefaults, {});
                return new LocalDatastore$1(this, storeOptions, storeInstanceOptions);
              } else {
                throw new Bottleneck2.prototype.BottleneckError(`Invalid datastore type: ${this.datastore}`);
              }
            }.call(this);
            this._queues.on("leftzero", () => {
              var ref;
              return (ref = this._store.heartbeat) != null ? typeof ref.ref === "function" ? ref.ref() : void 0 : void 0;
            });
            this._queues.on("zero", () => {
              var ref;
              return (ref = this._store.heartbeat) != null ? typeof ref.unref === "function" ? ref.unref() : void 0 : void 0;
            });
          }
          _validateOptions(options, invalid) {
            if (!(options != null && typeof options === "object" && invalid.length === 0)) {
              throw new Bottleneck2.prototype.BottleneckError("Bottleneck v2 takes a single object argument. Refer to https://github.com/SGrondin/bottleneck#upgrading-to-v2 if you're upgrading from Bottleneck v1.");
            }
          }
          ready() {
            return this._store.ready;
          }
          clients() {
            return this._store.clients;
          }
          channel() {
            return `b_${this.id}`;
          }
          channel_client() {
            return `b_${this.id}_${this._store.clientId}`;
          }
          publish(message) {
            return this._store.__publish__(message);
          }
          disconnect(flush = true) {
            return this._store.__disconnect__(flush);
          }
          chain(_limiter) {
            this._limiter = _limiter;
            return this;
          }
          queued(priority) {
            return this._queues.queued(priority);
          }
          clusterQueued() {
            return this._store.__queued__();
          }
          empty() {
            return this.queued() === 0 && this._submitLock.isEmpty();
          }
          running() {
            return this._store.__running__();
          }
          done() {
            return this._store.__done__();
          }
          jobStatus(id) {
            return this._states.jobStatus(id);
          }
          jobs(status) {
            return this._states.statusJobs(status);
          }
          counts() {
            return this._states.statusCounts();
          }
          _randomIndex() {
            return Math.random().toString(36).slice(2);
          }
          check(weight = 1) {
            return this._store.__check__(weight);
          }
          _clearGlobalState(index) {
            if (this._scheduled[index] != null) {
              clearTimeout(this._scheduled[index].expiration);
              delete this._scheduled[index];
              return true;
            } else {
              return false;
            }
          }
          async _free(index, job, options, eventInfo) {
            var e, running;
            try {
              ({ running } = await this._store.__free__(index, options.weight));
              this.Events.trigger("debug", `Freed ${options.id}`, eventInfo);
              if (running === 0 && this.empty()) {
                return this.Events.trigger("idle");
              }
            } catch (error1) {
              e = error1;
              return this.Events.trigger("error", e);
            }
          }
          _run(index, job, wait) {
            var clearGlobalState, free, run2;
            job.doRun();
            clearGlobalState = this._clearGlobalState.bind(this, index);
            run2 = this._run.bind(this, index, job);
            free = this._free.bind(this, index, job);
            return this._scheduled[index] = {
              timeout: setTimeout(() => {
                return job.doExecute(this._limiter, clearGlobalState, run2, free);
              }, wait),
              expiration: job.options.expiration != null ? setTimeout(function() {
                return job.doExpire(clearGlobalState, run2, free);
              }, wait + job.options.expiration) : void 0,
              job
            };
          }
          _drainOne(capacity) {
            return this._registerLock.schedule(() => {
              var args, index, next, options, queue;
              if (this.queued() === 0) {
                return this.Promise.resolve(null);
              }
              queue = this._queues.getFirst();
              ({ options, args } = next = queue.first());
              if (capacity != null && options.weight > capacity) {
                return this.Promise.resolve(null);
              }
              this.Events.trigger("debug", `Draining ${options.id}`, { args, options });
              index = this._randomIndex();
              return this._store.__register__(index, options.weight, options.expiration).then(({ success, wait, reservoir }) => {
                var empty;
                this.Events.trigger("debug", `Drained ${options.id}`, { success, args, options });
                if (success) {
                  queue.shift();
                  empty = this.empty();
                  if (empty) {
                    this.Events.trigger("empty");
                  }
                  if (reservoir === 0) {
                    this.Events.trigger("depleted", empty);
                  }
                  this._run(index, next, wait);
                  return this.Promise.resolve(options.weight);
                } else {
                  return this.Promise.resolve(null);
                }
              });
            });
          }
          _drainAll(capacity, total = 0) {
            return this._drainOne(capacity).then((drained) => {
              var newCapacity;
              if (drained != null) {
                newCapacity = capacity != null ? capacity - drained : capacity;
                return this._drainAll(newCapacity, total + drained);
              } else {
                return this.Promise.resolve(total);
              }
            }).catch((e) => {
              return this.Events.trigger("error", e);
            });
          }
          _dropAllQueued(message) {
            return this._queues.shiftAll(function(job) {
              return job.doDrop({ message });
            });
          }
          stop(options = {}) {
            var done, waitForExecuting;
            options = parser$5.load(options, this.stopDefaults);
            waitForExecuting = (at) => {
              var finished;
              finished = () => {
                var counts;
                counts = this._states.counts;
                return counts[0] + counts[1] + counts[2] + counts[3] === at;
              };
              return new this.Promise((resolve, reject) => {
                if (finished()) {
                  return resolve();
                } else {
                  return this.on("done", () => {
                    if (finished()) {
                      this.removeAllListeners("done");
                      return resolve();
                    }
                  });
                }
              });
            };
            done = options.dropWaitingJobs ? (this._run = function(index, next) {
              return next.doDrop({
                message: options.dropErrorMessage
              });
            }, this._drainOne = () => {
              return this.Promise.resolve(null);
            }, this._registerLock.schedule(() => {
              return this._submitLock.schedule(() => {
                var k, ref, v;
                ref = this._scheduled;
                for (k in ref) {
                  v = ref[k];
                  if (this.jobStatus(v.job.options.id) === "RUNNING") {
                    clearTimeout(v.timeout);
                    clearTimeout(v.expiration);
                    v.job.doDrop({
                      message: options.dropErrorMessage
                    });
                  }
                }
                this._dropAllQueued(options.dropErrorMessage);
                return waitForExecuting(0);
              });
            })) : this.schedule({
              priority: NUM_PRIORITIES$1 - 1,
              weight: 0
            }, () => {
              return waitForExecuting(1);
            });
            this._receive = function(job) {
              return job._reject(new Bottleneck2.prototype.BottleneckError(options.enqueueErrorMessage));
            };
            this.stop = () => {
              return this.Promise.reject(new Bottleneck2.prototype.BottleneckError("stop() has already been called"));
            };
            return done;
          }
          async _addToQueue(job) {
            var args, blocked, error, options, reachedHWM, shifted, strategy;
            ({ args, options } = job);
            try {
              ({ reachedHWM, blocked, strategy } = await this._store.__submit__(this.queued(), options.weight));
            } catch (error1) {
              error = error1;
              this.Events.trigger("debug", `Could not queue ${options.id}`, { args, options, error });
              job.doDrop({ error });
              return false;
            }
            if (blocked) {
              job.doDrop();
              return true;
            } else if (reachedHWM) {
              shifted = strategy === Bottleneck2.prototype.strategy.LEAK ? this._queues.shiftLastFrom(options.priority) : strategy === Bottleneck2.prototype.strategy.OVERFLOW_PRIORITY ? this._queues.shiftLastFrom(options.priority + 1) : strategy === Bottleneck2.prototype.strategy.OVERFLOW ? job : void 0;
              if (shifted != null) {
                shifted.doDrop();
              }
              if (shifted == null || strategy === Bottleneck2.prototype.strategy.OVERFLOW) {
                if (shifted == null) {
                  job.doDrop();
                }
                return reachedHWM;
              }
            }
            job.doQueue(reachedHWM, blocked);
            this._queues.push(job);
            await this._drainAll();
            return reachedHWM;
          }
          _receive(job) {
            if (this._states.jobStatus(job.options.id) != null) {
              job._reject(new Bottleneck2.prototype.BottleneckError(`A job with the same id already exists (id=${job.options.id})`));
              return false;
            } else {
              job.doReceive();
              return this._submitLock.schedule(this._addToQueue, job);
            }
          }
          submit(...args) {
            var cb, fn, job, options, ref, ref1, task;
            if (typeof args[0] === "function") {
              ref = args, [fn, ...args] = ref, [cb] = splice.call(args, -1);
              options = parser$5.load({}, this.jobDefaults);
            } else {
              ref1 = args, [options, fn, ...args] = ref1, [cb] = splice.call(args, -1);
              options = parser$5.load(options, this.jobDefaults);
            }
            task = (...args2) => {
              return new this.Promise(function(resolve, reject) {
                return fn(...args2, function(...args3) {
                  return (args3[0] != null ? reject : resolve)(args3);
                });
              });
            };
            job = new Job$1(task, args, options, this.jobDefaults, this.rejectOnDrop, this.Events, this._states, this.Promise);
            job.promise.then(function(args2) {
              return typeof cb === "function" ? cb(...args2) : void 0;
            }).catch(function(args2) {
              if (Array.isArray(args2)) {
                return typeof cb === "function" ? cb(...args2) : void 0;
              } else {
                return typeof cb === "function" ? cb(args2) : void 0;
              }
            });
            return this._receive(job);
          }
          schedule(...args) {
            var job, options, task;
            if (typeof args[0] === "function") {
              [task, ...args] = args;
              options = {};
            } else {
              [options, task, ...args] = args;
            }
            job = new Job$1(task, args, options, this.jobDefaults, this.rejectOnDrop, this.Events, this._states, this.Promise);
            this._receive(job);
            return job.promise;
          }
          wrap(fn) {
            var schedule, wrapped;
            schedule = this.schedule.bind(this);
            wrapped = function(...args) {
              return schedule(fn.bind(this), ...args);
            };
            wrapped.withOptions = function(options, ...args) {
              return schedule(options, fn, ...args);
            };
            return wrapped;
          }
          async updateSettings(options = {}) {
            await this._store.__updateSettings__(parser$5.overwrite(options, this.storeDefaults));
            parser$5.overwrite(options, this.instanceDefaults, this);
            return this;
          }
          currentReservoir() {
            return this._store.__currentReservoir__();
          }
          incrementReservoir(incr = 0) {
            return this._store.__incrementReservoir__(incr);
          }
        }
        Bottleneck2.default = Bottleneck2;
        Bottleneck2.Events = Events$4;
        Bottleneck2.version = Bottleneck2.prototype.version = require$$8.version;
        Bottleneck2.strategy = Bottleneck2.prototype.strategy = {
          LEAK: 1,
          OVERFLOW: 2,
          OVERFLOW_PRIORITY: 4,
          BLOCK: 3
        };
        Bottleneck2.BottleneckError = Bottleneck2.prototype.BottleneckError = BottleneckError_1;
        Bottleneck2.Group = Bottleneck2.prototype.Group = Group_1;
        Bottleneck2.RedisConnection = Bottleneck2.prototype.RedisConnection = require$$2;
        Bottleneck2.IORedisConnection = Bottleneck2.prototype.IORedisConnection = require$$3;
        Bottleneck2.Batcher = Bottleneck2.prototype.Batcher = Batcher_1;
        Bottleneck2.prototype.jobDefaults = {
          priority: DEFAULT_PRIORITY$1,
          weight: 1,
          expiration: null,
          id: "<no-id>"
        };
        Bottleneck2.prototype.storeDefaults = {
          maxConcurrent: null,
          minTime: 0,
          highWater: null,
          strategy: Bottleneck2.prototype.strategy.LEAK,
          penalty: null,
          reservoir: null,
          reservoirRefreshInterval: null,
          reservoirRefreshAmount: null,
          reservoirIncreaseInterval: null,
          reservoirIncreaseAmount: null,
          reservoirIncreaseMaximum: null
        };
        Bottleneck2.prototype.localStoreDefaults = {
          Promise,
          timeout: null,
          heartbeatInterval: 250
        };
        Bottleneck2.prototype.redisStoreDefaults = {
          Promise,
          timeout: null,
          heartbeatInterval: 5e3,
          clientTimeout: 1e4,
          Redis: null,
          clientOptions: {},
          clusterNodes: null,
          clearDatastore: false,
          connection: null
        };
        Bottleneck2.prototype.instanceDefaults = {
          datastore: "local",
          connection: null,
          id: "<no-id>",
          rejectOnDrop: true,
          trackDoneStatus: false,
          Promise
        };
        Bottleneck2.prototype.stopDefaults = {
          enqueueErrorMessage: "This limiter has been stopped and cannot accept new jobs.",
          dropWaitingJobs: true,
          dropErrorMessage: "This limiter has been stopped."
        };
        return Bottleneck2;
      }.call(commonjsGlobal);
      var Bottleneck_1 = Bottleneck;
      var lib = Bottleneck_1;
      return lib;
    });
  }
});

// node_modules/@octokit/plugin-retry/dist-node/index.js
var require_dist_node12 = __commonJS({
  "node_modules/@octokit/plugin-retry/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __create2 = Object.create;
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __getProtoOf2 = Object.getPrototypeOf;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toESM2 = (mod, isNodeMode, target) => (target = mod != null ? __create2(__getProtoOf2(mod)) : {}, __copyProps2(
      // If the importer is in node compatibility mode or this is not an ESM
      // file that has been converted to a CommonJS file using a Babel-
      // compatible transform (i.e. "__esModule" has not been set), then set
      // "default" to the CommonJS "module.exports" for node compatibility.
      isNodeMode || !mod || !mod.__esModule ? __defProp2(target, "default", { value: mod, enumerable: true }) : target,
      mod
    ));
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      VERSION: () => VERSION,
      retry: () => retry
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_core = require_dist_node8();
    async function errorRequest(state, octokit, error, options) {
      if (!error.request || !error.request.request) {
        throw error;
      }
      if (error.status >= 400 && !state.doNotRetry.includes(error.status)) {
        const retries = options.request.retries != null ? options.request.retries : state.retries;
        const retryAfter = Math.pow((options.request.retryCount || 0) + 1, 2);
        throw octokit.retry.retryRequest(error, retries, retryAfter);
      }
      throw error;
    }
    var import_light = __toESM2(require_light());
    var import_request_error = require_dist_node4();
    async function wrapRequest(state, octokit, request, options) {
      const limiter = new import_light.default();
      limiter.on("failed", function(error, info) {
        const maxRetries = ~~error.request.request.retries;
        const after = ~~error.request.request.retryAfter;
        options.request.retryCount = info.retryCount + 1;
        if (maxRetries > info.retryCount) {
          return after * state.retryAfterBaseValue;
        }
      });
      return limiter.schedule(
        requestWithGraphqlErrorHandling.bind(null, state, octokit, request),
        options
      );
    }
    async function requestWithGraphqlErrorHandling(state, octokit, request, options) {
      const response = await request(request, options);
      if (response.data && response.data.errors && /Something went wrong while executing your query/.test(
        response.data.errors[0].message
      )) {
        const error = new import_request_error.RequestError(response.data.errors[0].message, 500, {
          request: options,
          response
        });
        return errorRequest(state, octokit, error, options);
      }
      return response;
    }
    var VERSION = "6.0.0";
    function retry(octokit, octokitOptions) {
      const state = Object.assign(
        {
          enabled: true,
          retryAfterBaseValue: 1e3,
          doNotRetry: [400, 401, 403, 404, 422, 451],
          retries: 3
        },
        octokitOptions.retry
      );
      if (state.enabled) {
        octokit.hook.error("request", errorRequest.bind(null, state, octokit));
        octokit.hook.wrap("request", wrapRequest.bind(null, state, octokit));
      }
      return {
        retry: {
          retryRequest: (error, retries, retryAfter) => {
            error.request.request = Object.assign({}, error.request.request, {
              retries,
              retryAfter
            });
            return error;
          }
        }
      };
    }
    retry.VERSION = VERSION;
  }
});

// node_modules/@octokit/plugin-throttling/dist-node/index.js
var require_dist_node13 = __commonJS({
  "node_modules/@octokit/plugin-throttling/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __create2 = Object.create;
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __getProtoOf2 = Object.getPrototypeOf;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toESM2 = (mod, isNodeMode, target) => (target = mod != null ? __create2(__getProtoOf2(mod)) : {}, __copyProps2(
      // If the importer is in node compatibility mode or this is not an ESM
      // file that has been converted to a CommonJS file using a Babel-
      // compatible transform (i.e. "__esModule" has not been set), then set
      // "default" to the CommonJS "module.exports" for node compatibility.
      isNodeMode || !mod || !mod.__esModule ? __defProp2(target, "default", { value: mod, enumerable: true }) : target,
      mod
    ));
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      throttling: () => throttling
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_light = __toESM2(require_light());
    var import_core = require_dist_node8();
    var VERSION = "8.0.0";
    var noop = () => Promise.resolve();
    function wrapRequest(state, request, options) {
      return state.retryLimiter.schedule(doRequest, state, request, options);
    }
    async function doRequest(state, request, options) {
      const isWrite = options.method !== "GET" && options.method !== "HEAD";
      const { pathname } = new URL(options.url, "http://github.test");
      const isSearch = options.method === "GET" && pathname.startsWith("/search/");
      const isGraphQL = pathname.startsWith("/graphql");
      const retryCount = ~~request.retryCount;
      const jobOptions = retryCount > 0 ? { priority: 0, weight: 0 } : {};
      if (state.clustering) {
        jobOptions.expiration = 1e3 * 60;
      }
      if (isWrite || isGraphQL) {
        await state.write.key(state.id).schedule(jobOptions, noop);
      }
      if (isWrite && state.triggersNotification(pathname)) {
        await state.notifications.key(state.id).schedule(jobOptions, noop);
      }
      if (isSearch) {
        await state.search.key(state.id).schedule(jobOptions, noop);
      }
      const req = state.global.key(state.id).schedule(jobOptions, request, options);
      if (isGraphQL) {
        const res = await req;
        if (res.data.errors != null && // @ts-expect-error
        res.data.errors.some((error) => error.type === "RATE_LIMITED")) {
          const error = Object.assign(new Error("GraphQL Rate Limit Exceeded"), {
            response: res,
            data: res.data
          });
          throw error;
        }
      }
      return req;
    }
    var triggers_notification_paths_default = [
      "/orgs/{org}/invitations",
      "/orgs/{org}/invitations/{invitation_id}",
      "/orgs/{org}/teams/{team_slug}/discussions",
      "/orgs/{org}/teams/{team_slug}/discussions/{discussion_number}/comments",
      "/repos/{owner}/{repo}/collaborators/{username}",
      "/repos/{owner}/{repo}/commits/{commit_sha}/comments",
      "/repos/{owner}/{repo}/issues",
      "/repos/{owner}/{repo}/issues/{issue_number}/comments",
      "/repos/{owner}/{repo}/pulls",
      "/repos/{owner}/{repo}/pulls/{pull_number}/comments",
      "/repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies",
      "/repos/{owner}/{repo}/pulls/{pull_number}/merge",
      "/repos/{owner}/{repo}/pulls/{pull_number}/requested_reviewers",
      "/repos/{owner}/{repo}/pulls/{pull_number}/reviews",
      "/repos/{owner}/{repo}/releases",
      "/teams/{team_id}/discussions",
      "/teams/{team_id}/discussions/{discussion_number}/comments"
    ];
    function routeMatcher(paths) {
      const regexes = paths.map(
        (path2) => path2.split("/").map((c) => c.startsWith("{") ? "(?:.+?)" : c).join("/")
      );
      const regex2 = `^(?:${regexes.map((r) => `(?:${r})`).join("|")})[^/]*$`;
      return new RegExp(regex2, "i");
    }
    var regex = routeMatcher(triggers_notification_paths_default);
    var triggersNotification = regex.test.bind(regex);
    var groups = {};
    var createGroups = function(Bottleneck, common) {
      groups.global = new Bottleneck.Group({
        id: "octokit-global",
        maxConcurrent: 10,
        ...common
      });
      groups.search = new Bottleneck.Group({
        id: "octokit-search",
        maxConcurrent: 1,
        minTime: 2e3,
        ...common
      });
      groups.write = new Bottleneck.Group({
        id: "octokit-write",
        maxConcurrent: 1,
        minTime: 1e3,
        ...common
      });
      groups.notifications = new Bottleneck.Group({
        id: "octokit-notifications",
        maxConcurrent: 1,
        minTime: 3e3,
        ...common
      });
    };
    function throttling(octokit, octokitOptions) {
      const {
        enabled = true,
        Bottleneck = import_light.default,
        id = "no-id",
        timeout = 1e3 * 60 * 2,
        // Redis TTL: 2 minutes
        connection
      } = octokitOptions.throttle || {};
      if (!enabled) {
        return {};
      }
      const common = { connection, timeout };
      if (groups.global == null) {
        createGroups(Bottleneck, common);
      }
      const state = Object.assign(
        {
          clustering: connection != null,
          triggersNotification,
          fallbackSecondaryRateRetryAfter: 60,
          retryAfterBaseValue: 1e3,
          retryLimiter: new Bottleneck(),
          id,
          ...groups
        },
        octokitOptions.throttle
      );
      if (typeof state.onSecondaryRateLimit !== "function" || typeof state.onRateLimit !== "function") {
        throw new Error(`octokit/plugin-throttling error:
        You must pass the onSecondaryRateLimit and onRateLimit error handlers.
        See https://octokit.github.io/rest.js/#throttling

        const octokit = new Octokit({
          throttle: {
            onSecondaryRateLimit: (retryAfter, options) => {/* ... */},
            onRateLimit: (retryAfter, options) => {/* ... */}
          }
        })
    `);
      }
      const events = {};
      const emitter = new Bottleneck.Events(events);
      events.on("secondary-limit", state.onSecondaryRateLimit);
      events.on("rate-limit", state.onRateLimit);
      events.on(
        "error",
        (e) => octokit.log.warn("Error in throttling-plugin limit handler", e)
      );
      state.retryLimiter.on("failed", async function(error, info) {
        const [state2, request, options] = info.args;
        const { pathname } = new URL(options.url, "http://github.test");
        const shouldRetryGraphQL = pathname.startsWith("/graphql") && error.status !== 401;
        if (!(shouldRetryGraphQL || error.status === 403)) {
          return;
        }
        const retryCount = ~~request.retryCount;
        request.retryCount = retryCount;
        options.request.retryCount = retryCount;
        const { wantRetry, retryAfter = 0 } = await async function() {
          if (/\bsecondary rate\b/i.test(error.message)) {
            const retryAfter2 = Number(error.response.headers["retry-after"]) || state2.fallbackSecondaryRateRetryAfter;
            const wantRetry2 = await emitter.trigger(
              "secondary-limit",
              retryAfter2,
              options,
              octokit,
              retryCount
            );
            return { wantRetry: wantRetry2, retryAfter: retryAfter2 };
          }
          if (error.response.headers != null && error.response.headers["x-ratelimit-remaining"] === "0") {
            const rateLimitReset = new Date(
              ~~error.response.headers["x-ratelimit-reset"] * 1e3
            ).getTime();
            const retryAfter2 = Math.max(
              Math.ceil((rateLimitReset - Date.now()) / 1e3),
              0
            );
            const wantRetry2 = await emitter.trigger(
              "rate-limit",
              retryAfter2,
              options,
              octokit,
              retryCount
            );
            return { wantRetry: wantRetry2, retryAfter: retryAfter2 };
          }
          return {};
        }();
        if (wantRetry) {
          request.retryCount++;
          return retryAfter * state2.retryAfterBaseValue;
        }
      });
      octokit.hook.wrap("request", wrapRequest.bind(null, state));
      return {};
    }
    throttling.VERSION = VERSION;
    throttling.triggersNotification = triggersNotification;
  }
});

// node_modules/btoa-lite/btoa-node.js
var require_btoa_node = __commonJS({
  "node_modules/btoa-lite/btoa-node.js"(exports2, module2) {
    module2.exports = function btoa(str) {
      return new Buffer(str).toString("base64");
    };
  }
});

// node_modules/@octokit/oauth-authorization-url/dist-node/index.js
var require_dist_node14 = __commonJS({
  "node_modules/@octokit/oauth-authorization-url/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      oauthAuthorizationUrl: () => oauthAuthorizationUrl
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    function oauthAuthorizationUrl(options) {
      const clientType = options.clientType || "oauth-app";
      const baseUrl = options.baseUrl || "https://github.com";
      const result = {
        clientType,
        allowSignup: options.allowSignup === false ? false : true,
        clientId: options.clientId,
        login: options.login || null,
        redirectUrl: options.redirectUrl || null,
        state: options.state || Math.random().toString(36).substr(2),
        url: ""
      };
      if (clientType === "oauth-app") {
        const scopes = "scopes" in options ? options.scopes : [];
        result.scopes = typeof scopes === "string" ? scopes.split(/[,\s]+/).filter(Boolean) : scopes;
      }
      result.url = urlBuilderAuthorize(`${baseUrl}/login/oauth/authorize`, result);
      return result;
    }
    function urlBuilderAuthorize(base, options) {
      const map = {
        allowSignup: "allow_signup",
        clientId: "client_id",
        login: "login",
        redirectUrl: "redirect_uri",
        scopes: "scope",
        state: "state"
      };
      let url = base;
      Object.keys(map).filter((k) => options[k] !== null).filter((k) => {
        if (k !== "scopes")
          return true;
        if (options.clientType === "github-app")
          return false;
        return !Array.isArray(options[k]) || options[k].length > 0;
      }).map((key) => [map[key], `${options[key]}`]).forEach(([key, value], index) => {
        url += index === 0 ? `?` : "&";
        url += `${key}=${encodeURIComponent(value)}`;
      });
      return url;
    }
  }
});

// node_modules/@octokit/oauth-methods/dist-node/index.js
var require_dist_node15 = __commonJS({
  "node_modules/@octokit/oauth-methods/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __create2 = Object.create;
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __getProtoOf2 = Object.getPrototypeOf;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toESM2 = (mod, isNodeMode, target) => (target = mod != null ? __create2(__getProtoOf2(mod)) : {}, __copyProps2(
      // If the importer is in node compatibility mode or this is not an ESM
      // file that has been converted to a CommonJS file using a Babel-
      // compatible transform (i.e. "__esModule" has not been set), then set
      // "default" to the CommonJS "module.exports" for node compatibility.
      isNodeMode || !mod || !mod.__esModule ? __defProp2(target, "default", { value: mod, enumerable: true }) : target,
      mod
    ));
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      VERSION: () => VERSION,
      checkToken: () => checkToken,
      createDeviceCode: () => createDeviceCode,
      deleteAuthorization: () => deleteAuthorization,
      deleteToken: () => deleteToken,
      exchangeDeviceCode: () => exchangeDeviceCode,
      exchangeWebFlowCode: () => exchangeWebFlowCode,
      getWebFlowAuthorizationUrl: () => getWebFlowAuthorizationUrl,
      refreshToken: () => refreshToken,
      resetToken: () => resetToken,
      scopeToken: () => scopeToken
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var VERSION = "4.0.1";
    var import_oauth_authorization_url = require_dist_node14();
    var import_request = require_dist_node5();
    var import_request_error = require_dist_node4();
    function requestToOAuthBaseUrl(request) {
      const endpointDefaults = request.endpoint.DEFAULTS;
      return /^https:\/\/(api\.)?github\.com$/.test(endpointDefaults.baseUrl) ? "https://github.com" : endpointDefaults.baseUrl.replace("/api/v3", "");
    }
    async function oauthRequest(request, route, parameters) {
      const withOAuthParameters = {
        baseUrl: requestToOAuthBaseUrl(request),
        headers: {
          accept: "application/json"
        },
        ...parameters
      };
      const response = await request(route, withOAuthParameters);
      if ("error" in response.data) {
        const error = new import_request_error.RequestError(
          `${response.data.error_description} (${response.data.error}, ${response.data.error_uri})`,
          400,
          {
            request: request.endpoint.merge(
              route,
              withOAuthParameters
            ),
            headers: response.headers
          }
        );
        error.response = response;
        throw error;
      }
      return response;
    }
    function getWebFlowAuthorizationUrl({
      request = import_request.request,
      ...options
    }) {
      const baseUrl = requestToOAuthBaseUrl(request);
      return (0, import_oauth_authorization_url.oauthAuthorizationUrl)({
        ...options,
        baseUrl
      });
    }
    var import_request2 = require_dist_node5();
    async function exchangeWebFlowCode(options) {
      const request = options.request || /* istanbul ignore next: we always pass a custom request in tests */
      import_request2.request;
      const response = await oauthRequest(
        request,
        "POST /login/oauth/access_token",
        {
          client_id: options.clientId,
          client_secret: options.clientSecret,
          code: options.code,
          redirect_uri: options.redirectUrl
        }
      );
      const authentication = {
        clientType: options.clientType,
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        token: response.data.access_token,
        scopes: response.data.scope.split(/\s+/).filter(Boolean)
      };
      if (options.clientType === "github-app") {
        if ("refresh_token" in response.data) {
          const apiTimeInMs = new Date(response.headers.date).getTime();
          authentication.refreshToken = response.data.refresh_token, authentication.expiresAt = toTimestamp(
            apiTimeInMs,
            response.data.expires_in
          ), authentication.refreshTokenExpiresAt = toTimestamp(
            apiTimeInMs,
            response.data.refresh_token_expires_in
          );
        }
        delete authentication.scopes;
      }
      return { ...response, authentication };
    }
    function toTimestamp(apiTimeInMs, expirationInSeconds) {
      return new Date(apiTimeInMs + expirationInSeconds * 1e3).toISOString();
    }
    var import_request3 = require_dist_node5();
    async function createDeviceCode(options) {
      const request = options.request || /* istanbul ignore next: we always pass a custom request in tests */
      import_request3.request;
      const parameters = {
        client_id: options.clientId
      };
      if ("scopes" in options && Array.isArray(options.scopes)) {
        parameters.scope = options.scopes.join(" ");
      }
      return oauthRequest(request, "POST /login/device/code", parameters);
    }
    var import_request4 = require_dist_node5();
    async function exchangeDeviceCode(options) {
      const request = options.request || /* istanbul ignore next: we always pass a custom request in tests */
      import_request4.request;
      const response = await oauthRequest(
        request,
        "POST /login/oauth/access_token",
        {
          client_id: options.clientId,
          device_code: options.code,
          grant_type: "urn:ietf:params:oauth:grant-type:device_code"
        }
      );
      const authentication = {
        clientType: options.clientType,
        clientId: options.clientId,
        token: response.data.access_token,
        scopes: response.data.scope.split(/\s+/).filter(Boolean)
      };
      if ("clientSecret" in options) {
        authentication.clientSecret = options.clientSecret;
      }
      if (options.clientType === "github-app") {
        if ("refresh_token" in response.data) {
          const apiTimeInMs = new Date(response.headers.date).getTime();
          authentication.refreshToken = response.data.refresh_token, authentication.expiresAt = toTimestamp2(
            apiTimeInMs,
            response.data.expires_in
          ), authentication.refreshTokenExpiresAt = toTimestamp2(
            apiTimeInMs,
            response.data.refresh_token_expires_in
          );
        }
        delete authentication.scopes;
      }
      return { ...response, authentication };
    }
    function toTimestamp2(apiTimeInMs, expirationInSeconds) {
      return new Date(apiTimeInMs + expirationInSeconds * 1e3).toISOString();
    }
    var import_request5 = require_dist_node5();
    var import_btoa_lite = __toESM2(require_btoa_node());
    async function checkToken(options) {
      const request = options.request || /* istanbul ignore next: we always pass a custom request in tests */
      import_request5.request;
      const response = await request("POST /applications/{client_id}/token", {
        headers: {
          authorization: `basic ${(0, import_btoa_lite.default)(
            `${options.clientId}:${options.clientSecret}`
          )}`
        },
        client_id: options.clientId,
        access_token: options.token
      });
      const authentication = {
        clientType: options.clientType,
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        token: options.token,
        scopes: response.data.scopes
      };
      if (response.data.expires_at)
        authentication.expiresAt = response.data.expires_at;
      if (options.clientType === "github-app") {
        delete authentication.scopes;
      }
      return { ...response, authentication };
    }
    var import_request6 = require_dist_node5();
    async function refreshToken(options) {
      const request = options.request || /* istanbul ignore next: we always pass a custom request in tests */
      import_request6.request;
      const response = await oauthRequest(
        request,
        "POST /login/oauth/access_token",
        {
          client_id: options.clientId,
          client_secret: options.clientSecret,
          grant_type: "refresh_token",
          refresh_token: options.refreshToken
        }
      );
      const apiTimeInMs = new Date(response.headers.date).getTime();
      const authentication = {
        clientType: "github-app",
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        token: response.data.access_token,
        refreshToken: response.data.refresh_token,
        expiresAt: toTimestamp3(apiTimeInMs, response.data.expires_in),
        refreshTokenExpiresAt: toTimestamp3(
          apiTimeInMs,
          response.data.refresh_token_expires_in
        )
      };
      return { ...response, authentication };
    }
    function toTimestamp3(apiTimeInMs, expirationInSeconds) {
      return new Date(apiTimeInMs + expirationInSeconds * 1e3).toISOString();
    }
    var import_request7 = require_dist_node5();
    var import_btoa_lite2 = __toESM2(require_btoa_node());
    async function scopeToken(options) {
      const {
        request: optionsRequest,
        clientType,
        clientId,
        clientSecret,
        token,
        ...requestOptions
      } = options;
      const request = optionsRequest || /* istanbul ignore next: we always pass a custom request in tests */
      import_request7.request;
      const response = await request(
        "POST /applications/{client_id}/token/scoped",
        {
          headers: {
            authorization: `basic ${(0, import_btoa_lite2.default)(`${clientId}:${clientSecret}`)}`
          },
          client_id: clientId,
          access_token: token,
          ...requestOptions
        }
      );
      const authentication = Object.assign(
        {
          clientType,
          clientId,
          clientSecret,
          token: response.data.token
        },
        response.data.expires_at ? { expiresAt: response.data.expires_at } : {}
      );
      return { ...response, authentication };
    }
    var import_request8 = require_dist_node5();
    var import_btoa_lite3 = __toESM2(require_btoa_node());
    async function resetToken(options) {
      const request = options.request || /* istanbul ignore next: we always pass a custom request in tests */
      import_request8.request;
      const auth = (0, import_btoa_lite3.default)(`${options.clientId}:${options.clientSecret}`);
      const response = await request(
        "PATCH /applications/{client_id}/token",
        {
          headers: {
            authorization: `basic ${auth}`
          },
          client_id: options.clientId,
          access_token: options.token
        }
      );
      const authentication = {
        clientType: options.clientType,
        clientId: options.clientId,
        clientSecret: options.clientSecret,
        token: response.data.token,
        scopes: response.data.scopes
      };
      if (response.data.expires_at)
        authentication.expiresAt = response.data.expires_at;
      if (options.clientType === "github-app") {
        delete authentication.scopes;
      }
      return { ...response, authentication };
    }
    var import_request9 = require_dist_node5();
    var import_btoa_lite4 = __toESM2(require_btoa_node());
    async function deleteToken(options) {
      const request = options.request || /* istanbul ignore next: we always pass a custom request in tests */
      import_request9.request;
      const auth = (0, import_btoa_lite4.default)(`${options.clientId}:${options.clientSecret}`);
      return request(
        "DELETE /applications/{client_id}/token",
        {
          headers: {
            authorization: `basic ${auth}`
          },
          client_id: options.clientId,
          access_token: options.token
        }
      );
    }
    var import_request10 = require_dist_node5();
    var import_btoa_lite5 = __toESM2(require_btoa_node());
    async function deleteAuthorization(options) {
      const request = options.request || /* istanbul ignore next: we always pass a custom request in tests */
      import_request10.request;
      const auth = (0, import_btoa_lite5.default)(`${options.clientId}:${options.clientSecret}`);
      return request(
        "DELETE /applications/{client_id}/grant",
        {
          headers: {
            authorization: `basic ${auth}`
          },
          client_id: options.clientId,
          access_token: options.token
        }
      );
    }
  }
});

// node_modules/@octokit/auth-oauth-device/dist-node/index.js
var require_dist_node16 = __commonJS({
  "node_modules/@octokit/auth-oauth-device/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      createOAuthDeviceAuth: () => createOAuthDeviceAuth
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_universal_user_agent = require_dist_node();
    var import_request = require_dist_node5();
    var import_oauth_methods = require_dist_node15();
    async function getOAuthAccessToken(state, options) {
      const cachedAuthentication = getCachedAuthentication(state, options.auth);
      if (cachedAuthentication)
        return cachedAuthentication;
      const { data: verification } = await (0, import_oauth_methods.createDeviceCode)({
        clientType: state.clientType,
        clientId: state.clientId,
        request: options.request || state.request,
        // @ts-expect-error the extra code to make TS happy is not worth it
        scopes: options.auth.scopes || state.scopes
      });
      await state.onVerification(verification);
      const authentication = await waitForAccessToken(
        options.request || state.request,
        state.clientId,
        state.clientType,
        verification
      );
      state.authentication = authentication;
      return authentication;
    }
    function getCachedAuthentication(state, auth2) {
      if (auth2.refresh === true)
        return false;
      if (!state.authentication)
        return false;
      if (state.clientType === "github-app") {
        return state.authentication;
      }
      const authentication = state.authentication;
      const newScope = ("scopes" in auth2 && auth2.scopes || state.scopes).join(
        " "
      );
      const currentScope = authentication.scopes.join(" ");
      return newScope === currentScope ? authentication : false;
    }
    async function wait(seconds) {
      await new Promise((resolve) => setTimeout(resolve, seconds * 1e3));
    }
    async function waitForAccessToken(request, clientId, clientType, verification) {
      try {
        const options = {
          clientId,
          request,
          code: verification.device_code
        };
        const { authentication } = clientType === "oauth-app" ? await (0, import_oauth_methods.exchangeDeviceCode)({
          ...options,
          clientType: "oauth-app"
        }) : await (0, import_oauth_methods.exchangeDeviceCode)({
          ...options,
          clientType: "github-app"
        });
        return {
          type: "token",
          tokenType: "oauth",
          ...authentication
        };
      } catch (error) {
        if (!error.response)
          throw error;
        const errorType = error.response.data.error;
        if (errorType === "authorization_pending") {
          await wait(verification.interval);
          return waitForAccessToken(request, clientId, clientType, verification);
        }
        if (errorType === "slow_down") {
          await wait(verification.interval + 5);
          return waitForAccessToken(request, clientId, clientType, verification);
        }
        throw error;
      }
    }
    async function auth(state, authOptions) {
      return getOAuthAccessToken(state, {
        auth: authOptions
      });
    }
    async function hook(state, request, route, parameters) {
      let endpoint = request.endpoint.merge(
        route,
        parameters
      );
      if (/\/login\/(oauth\/access_token|device\/code)$/.test(endpoint.url)) {
        return request(endpoint);
      }
      const { token } = await getOAuthAccessToken(state, {
        request,
        auth: { type: "oauth" }
      });
      endpoint.headers.authorization = `token ${token}`;
      return request(endpoint);
    }
    var VERSION = "6.0.1";
    function createOAuthDeviceAuth(options) {
      const requestWithDefaults = options.request || import_request.request.defaults({
        headers: {
          "user-agent": `octokit-auth-oauth-device.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`
        }
      });
      const { request = requestWithDefaults, ...otherOptions } = options;
      const state = options.clientType === "github-app" ? {
        ...otherOptions,
        clientType: "github-app",
        request
      } : {
        ...otherOptions,
        clientType: "oauth-app",
        request,
        scopes: options.scopes || []
      };
      if (!options.clientId) {
        throw new Error(
          '[@octokit/auth-oauth-device] "clientId" option must be set (https://github.com/octokit/auth-oauth-device.js#usage)'
        );
      }
      if (!options.onVerification) {
        throw new Error(
          '[@octokit/auth-oauth-device] "onVerification" option must be a function (https://github.com/octokit/auth-oauth-device.js#usage)'
        );
      }
      return Object.assign(auth.bind(null, state), {
        hook: hook.bind(null, state)
      });
    }
  }
});

// node_modules/@octokit/auth-oauth-user/dist-node/index.js
var require_dist_node17 = __commonJS({
  "node_modules/@octokit/auth-oauth-user/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __create2 = Object.create;
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __getProtoOf2 = Object.getPrototypeOf;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toESM2 = (mod, isNodeMode, target) => (target = mod != null ? __create2(__getProtoOf2(mod)) : {}, __copyProps2(
      // If the importer is in node compatibility mode or this is not an ESM
      // file that has been converted to a CommonJS file using a Babel-
      // compatible transform (i.e. "__esModule" has not been set), then set
      // "default" to the CommonJS "module.exports" for node compatibility.
      isNodeMode || !mod || !mod.__esModule ? __defProp2(target, "default", { value: mod, enumerable: true }) : target,
      mod
    ));
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      createOAuthUserAuth: () => createOAuthUserAuth2,
      requiresBasicAuth: () => requiresBasicAuth
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_universal_user_agent = require_dist_node();
    var import_request = require_dist_node5();
    var VERSION = "4.0.1";
    var import_auth_oauth_device = require_dist_node16();
    var import_oauth_methods = require_dist_node15();
    async function getAuthentication(state) {
      if ("code" in state.strategyOptions) {
        const { authentication } = await (0, import_oauth_methods.exchangeWebFlowCode)({
          clientId: state.clientId,
          clientSecret: state.clientSecret,
          clientType: state.clientType,
          onTokenCreated: state.onTokenCreated,
          ...state.strategyOptions,
          request: state.request
        });
        return {
          type: "token",
          tokenType: "oauth",
          ...authentication
        };
      }
      if ("onVerification" in state.strategyOptions) {
        const deviceAuth = (0, import_auth_oauth_device.createOAuthDeviceAuth)({
          clientType: state.clientType,
          clientId: state.clientId,
          onTokenCreated: state.onTokenCreated,
          ...state.strategyOptions,
          request: state.request
        });
        const authentication = await deviceAuth({
          type: "oauth"
        });
        return {
          clientSecret: state.clientSecret,
          ...authentication
        };
      }
      if ("token" in state.strategyOptions) {
        return {
          type: "token",
          tokenType: "oauth",
          clientId: state.clientId,
          clientSecret: state.clientSecret,
          clientType: state.clientType,
          onTokenCreated: state.onTokenCreated,
          ...state.strategyOptions
        };
      }
      throw new Error("[@octokit/auth-oauth-user] Invalid strategy options");
    }
    var import_oauth_methods2 = require_dist_node15();
    async function auth(state, options = {}) {
      var _a, _b;
      if (!state.authentication) {
        state.authentication = state.clientType === "oauth-app" ? await getAuthentication(state) : await getAuthentication(state);
      }
      if (state.authentication.invalid) {
        throw new Error("[@octokit/auth-oauth-user] Token is invalid");
      }
      const currentAuthentication = state.authentication;
      if ("expiresAt" in currentAuthentication) {
        if (options.type === "refresh" || new Date(currentAuthentication.expiresAt) < /* @__PURE__ */ new Date()) {
          const { authentication } = await (0, import_oauth_methods2.refreshToken)({
            clientType: "github-app",
            clientId: state.clientId,
            clientSecret: state.clientSecret,
            refreshToken: currentAuthentication.refreshToken,
            request: state.request
          });
          state.authentication = {
            tokenType: "oauth",
            type: "token",
            ...authentication
          };
        }
      }
      if (options.type === "refresh") {
        if (state.clientType === "oauth-app") {
          throw new Error(
            "[@octokit/auth-oauth-user] OAuth Apps do not support expiring tokens"
          );
        }
        if (!currentAuthentication.hasOwnProperty("expiresAt")) {
          throw new Error("[@octokit/auth-oauth-user] Refresh token missing");
        }
        await ((_a = state.onTokenCreated) == null ? void 0 : _a.call(state, state.authentication, {
          type: options.type
        }));
      }
      if (options.type === "check" || options.type === "reset") {
        const method = options.type === "check" ? import_oauth_methods2.checkToken : import_oauth_methods2.resetToken;
        try {
          const { authentication } = await method({
            // @ts-expect-error making TS happy would require unnecessary code so no
            clientType: state.clientType,
            clientId: state.clientId,
            clientSecret: state.clientSecret,
            token: state.authentication.token,
            request: state.request
          });
          state.authentication = {
            tokenType: "oauth",
            type: "token",
            // @ts-expect-error TBD
            ...authentication
          };
          if (options.type === "reset") {
            await ((_b = state.onTokenCreated) == null ? void 0 : _b.call(state, state.authentication, {
              type: options.type
            }));
          }
          return state.authentication;
        } catch (error) {
          if (error.status === 404) {
            error.message = "[@octokit/auth-oauth-user] Token is invalid";
            state.authentication.invalid = true;
          }
          throw error;
        }
      }
      if (options.type === "delete" || options.type === "deleteAuthorization") {
        const method = options.type === "delete" ? import_oauth_methods2.deleteToken : import_oauth_methods2.deleteAuthorization;
        try {
          await method({
            // @ts-expect-error making TS happy would require unnecessary code so no
            clientType: state.clientType,
            clientId: state.clientId,
            clientSecret: state.clientSecret,
            token: state.authentication.token,
            request: state.request
          });
        } catch (error) {
          if (error.status !== 404)
            throw error;
        }
        state.authentication.invalid = true;
        return state.authentication;
      }
      return state.authentication;
    }
    var import_btoa_lite = __toESM2(require_btoa_node());
    var ROUTES_REQUIRING_BASIC_AUTH = /\/applications\/[^/]+\/(token|grant)s?/;
    function requiresBasicAuth(url) {
      return url && ROUTES_REQUIRING_BASIC_AUTH.test(url);
    }
    async function hook(state, request, route, parameters = {}) {
      const endpoint = request.endpoint.merge(
        route,
        parameters
      );
      if (/\/login\/(oauth\/access_token|device\/code)$/.test(endpoint.url)) {
        return request(endpoint);
      }
      if (requiresBasicAuth(endpoint.url)) {
        const credentials = (0, import_btoa_lite.default)(`${state.clientId}:${state.clientSecret}`);
        endpoint.headers.authorization = `basic ${credentials}`;
        return request(endpoint);
      }
      const { token } = state.clientType === "oauth-app" ? await auth({ ...state, request }) : await auth({ ...state, request });
      endpoint.headers.authorization = "token " + token;
      return request(endpoint);
    }
    function createOAuthUserAuth2({
      clientId,
      clientSecret,
      clientType = "oauth-app",
      request = import_request.request.defaults({
        headers: {
          "user-agent": `octokit-auth-oauth-app.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`
        }
      }),
      onTokenCreated,
      ...strategyOptions
    }) {
      const state = Object.assign({
        clientType,
        clientId,
        clientSecret,
        onTokenCreated,
        strategyOptions,
        request
      });
      return Object.assign(auth.bind(null, state), {
        // @ts-expect-error not worth the extra code needed to appease TS
        hook: hook.bind(null, state)
      });
    }
    createOAuthUserAuth2.VERSION = VERSION;
  }
});

// node_modules/@octokit/auth-oauth-app/dist-node/index.js
var require_dist_node18 = __commonJS({
  "node_modules/@octokit/auth-oauth-app/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __create2 = Object.create;
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __getProtoOf2 = Object.getPrototypeOf;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toESM2 = (mod, isNodeMode, target) => (target = mod != null ? __create2(__getProtoOf2(mod)) : {}, __copyProps2(
      // If the importer is in node compatibility mode or this is not an ESM
      // file that has been converted to a CommonJS file using a Babel-
      // compatible transform (i.e. "__esModule" has not been set), then set
      // "default" to the CommonJS "module.exports" for node compatibility.
      isNodeMode || !mod || !mod.__esModule ? __defProp2(target, "default", { value: mod, enumerable: true }) : target,
      mod
    ));
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      createOAuthAppAuth: () => createOAuthAppAuth,
      createOAuthUserAuth: () => import_auth_oauth_user3.createOAuthUserAuth
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_universal_user_agent = require_dist_node();
    var import_request = require_dist_node5();
    var import_btoa_lite = __toESM2(require_btoa_node());
    var import_auth_oauth_user = require_dist_node17();
    async function auth(state, authOptions) {
      if (authOptions.type === "oauth-app") {
        return {
          type: "oauth-app",
          clientId: state.clientId,
          clientSecret: state.clientSecret,
          clientType: state.clientType,
          headers: {
            authorization: `basic ${(0, import_btoa_lite.default)(
              `${state.clientId}:${state.clientSecret}`
            )}`
          }
        };
      }
      if ("factory" in authOptions) {
        const { type, ...options } = {
          ...authOptions,
          ...state
        };
        return authOptions.factory(options);
      }
      const common = {
        clientId: state.clientId,
        clientSecret: state.clientSecret,
        request: state.request,
        ...authOptions
      };
      const userAuth = state.clientType === "oauth-app" ? await (0, import_auth_oauth_user.createOAuthUserAuth)({
        ...common,
        clientType: state.clientType
      }) : await (0, import_auth_oauth_user.createOAuthUserAuth)({
        ...common,
        clientType: state.clientType
      });
      return userAuth();
    }
    var import_btoa_lite2 = __toESM2(require_btoa_node());
    var import_auth_oauth_user2 = require_dist_node17();
    async function hook(state, request2, route, parameters) {
      let endpoint = request2.endpoint.merge(
        route,
        parameters
      );
      if (/\/login\/(oauth\/access_token|device\/code)$/.test(endpoint.url)) {
        return request2(endpoint);
      }
      if (state.clientType === "github-app" && !(0, import_auth_oauth_user2.requiresBasicAuth)(endpoint.url)) {
        throw new Error(
          `[@octokit/auth-oauth-app] GitHub Apps cannot use their client ID/secret for basic authentication for endpoints other than "/applications/{client_id}/**". "${endpoint.method} ${endpoint.url}" is not supported.`
        );
      }
      const credentials = (0, import_btoa_lite2.default)(`${state.clientId}:${state.clientSecret}`);
      endpoint.headers.authorization = `basic ${credentials}`;
      try {
        return await request2(endpoint);
      } catch (error) {
        if (error.status !== 401)
          throw error;
        error.message = `[@octokit/auth-oauth-app] "${endpoint.method} ${endpoint.url}" does not support clientId/clientSecret basic authentication.`;
        throw error;
      }
    }
    var VERSION = "7.0.1";
    var import_auth_oauth_user3 = require_dist_node17();
    function createOAuthAppAuth(options) {
      const state = Object.assign(
        {
          request: import_request.request.defaults({
            headers: {
              "user-agent": `octokit-auth-oauth-app.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`
            }
          }),
          clientType: "oauth-app"
        },
        options
      );
      return Object.assign(auth.bind(null, state), {
        hook: hook.bind(null, state)
      });
    }
  }
});

// node_modules/safe-buffer/index.js
var require_safe_buffer = __commonJS({
  "node_modules/safe-buffer/index.js"(exports2, module2) {
    var buffer = require("buffer");
    var Buffer2 = buffer.Buffer;
    function copyProps(src, dst) {
      for (var key in src) {
        dst[key] = src[key];
      }
    }
    if (Buffer2.from && Buffer2.alloc && Buffer2.allocUnsafe && Buffer2.allocUnsafeSlow) {
      module2.exports = buffer;
    } else {
      copyProps(buffer, exports2);
      exports2.Buffer = SafeBuffer;
    }
    function SafeBuffer(arg, encodingOrOffset, length) {
      return Buffer2(arg, encodingOrOffset, length);
    }
    copyProps(Buffer2, SafeBuffer);
    SafeBuffer.from = function(arg, encodingOrOffset, length) {
      if (typeof arg === "number") {
        throw new TypeError("Argument must not be a number");
      }
      return Buffer2(arg, encodingOrOffset, length);
    };
    SafeBuffer.alloc = function(size, fill, encoding) {
      if (typeof size !== "number") {
        throw new TypeError("Argument must be a number");
      }
      var buf = Buffer2(size);
      if (fill !== void 0) {
        if (typeof encoding === "string") {
          buf.fill(fill, encoding);
        } else {
          buf.fill(fill);
        }
      } else {
        buf.fill(0);
      }
      return buf;
    };
    SafeBuffer.allocUnsafe = function(size) {
      if (typeof size !== "number") {
        throw new TypeError("Argument must be a number");
      }
      return Buffer2(size);
    };
    SafeBuffer.allocUnsafeSlow = function(size) {
      if (typeof size !== "number") {
        throw new TypeError("Argument must be a number");
      }
      return buffer.SlowBuffer(size);
    };
  }
});

// node_modules/jws/lib/data-stream.js
var require_data_stream = __commonJS({
  "node_modules/jws/lib/data-stream.js"(exports2, module2) {
    var Buffer2 = require_safe_buffer().Buffer;
    var Stream = require("stream");
    var util = require("util");
    function DataStream(data) {
      this.buffer = null;
      this.writable = true;
      this.readable = true;
      if (!data) {
        this.buffer = Buffer2.alloc(0);
        return this;
      }
      if (typeof data.pipe === "function") {
        this.buffer = Buffer2.alloc(0);
        data.pipe(this);
        return this;
      }
      if (data.length || typeof data === "object") {
        this.buffer = data;
        this.writable = false;
        process.nextTick(function() {
          this.emit("end", data);
          this.readable = false;
          this.emit("close");
        }.bind(this));
        return this;
      }
      throw new TypeError("Unexpected data type (" + typeof data + ")");
    }
    util.inherits(DataStream, Stream);
    DataStream.prototype.write = function write(data) {
      this.buffer = Buffer2.concat([this.buffer, Buffer2.from(data)]);
      this.emit("data", data);
    };
    DataStream.prototype.end = function end(data) {
      if (data)
        this.write(data);
      this.emit("end", data);
      this.emit("close");
      this.writable = false;
      this.readable = false;
    };
    module2.exports = DataStream;
  }
});

// node_modules/buffer-equal-constant-time/index.js
var require_buffer_equal_constant_time = __commonJS({
  "node_modules/buffer-equal-constant-time/index.js"(exports2, module2) {
    "use strict";
    var Buffer2 = require("buffer").Buffer;
    var SlowBuffer = require("buffer").SlowBuffer;
    module2.exports = bufferEq;
    function bufferEq(a, b) {
      if (!Buffer2.isBuffer(a) || !Buffer2.isBuffer(b)) {
        return false;
      }
      if (a.length !== b.length) {
        return false;
      }
      var c = 0;
      for (var i = 0; i < a.length; i++) {
        c |= a[i] ^ b[i];
      }
      return c === 0;
    }
    bufferEq.install = function() {
      Buffer2.prototype.equal = SlowBuffer.prototype.equal = function equal(that) {
        return bufferEq(this, that);
      };
    };
    var origBufEqual = Buffer2.prototype.equal;
    var origSlowBufEqual = SlowBuffer.prototype.equal;
    bufferEq.restore = function() {
      Buffer2.prototype.equal = origBufEqual;
      SlowBuffer.prototype.equal = origSlowBufEqual;
    };
  }
});

// node_modules/ecdsa-sig-formatter/src/param-bytes-for-alg.js
var require_param_bytes_for_alg = __commonJS({
  "node_modules/ecdsa-sig-formatter/src/param-bytes-for-alg.js"(exports2, module2) {
    "use strict";
    function getParamSize(keySize) {
      var result = (keySize / 8 | 0) + (keySize % 8 === 0 ? 0 : 1);
      return result;
    }
    var paramBytesForAlg = {
      ES256: getParamSize(256),
      ES384: getParamSize(384),
      ES512: getParamSize(521)
    };
    function getParamBytesForAlg(alg) {
      var paramBytes = paramBytesForAlg[alg];
      if (paramBytes) {
        return paramBytes;
      }
      throw new Error('Unknown algorithm "' + alg + '"');
    }
    module2.exports = getParamBytesForAlg;
  }
});

// node_modules/ecdsa-sig-formatter/src/ecdsa-sig-formatter.js
var require_ecdsa_sig_formatter = __commonJS({
  "node_modules/ecdsa-sig-formatter/src/ecdsa-sig-formatter.js"(exports2, module2) {
    "use strict";
    var Buffer2 = require_safe_buffer().Buffer;
    var getParamBytesForAlg = require_param_bytes_for_alg();
    var MAX_OCTET = 128;
    var CLASS_UNIVERSAL = 0;
    var PRIMITIVE_BIT = 32;
    var TAG_SEQ = 16;
    var TAG_INT = 2;
    var ENCODED_TAG_SEQ = TAG_SEQ | PRIMITIVE_BIT | CLASS_UNIVERSAL << 6;
    var ENCODED_TAG_INT = TAG_INT | CLASS_UNIVERSAL << 6;
    function base64Url(base64) {
      return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    }
    function signatureAsBuffer(signature) {
      if (Buffer2.isBuffer(signature)) {
        return signature;
      } else if ("string" === typeof signature) {
        return Buffer2.from(signature, "base64");
      }
      throw new TypeError("ECDSA signature must be a Base64 string or a Buffer");
    }
    function derToJose(signature, alg) {
      signature = signatureAsBuffer(signature);
      var paramBytes = getParamBytesForAlg(alg);
      var maxEncodedParamLength = paramBytes + 1;
      var inputLength = signature.length;
      var offset = 0;
      if (signature[offset++] !== ENCODED_TAG_SEQ) {
        throw new Error('Could not find expected "seq"');
      }
      var seqLength = signature[offset++];
      if (seqLength === (MAX_OCTET | 1)) {
        seqLength = signature[offset++];
      }
      if (inputLength - offset < seqLength) {
        throw new Error('"seq" specified length of "' + seqLength + '", only "' + (inputLength - offset) + '" remaining');
      }
      if (signature[offset++] !== ENCODED_TAG_INT) {
        throw new Error('Could not find expected "int" for "r"');
      }
      var rLength = signature[offset++];
      if (inputLength - offset - 2 < rLength) {
        throw new Error('"r" specified length of "' + rLength + '", only "' + (inputLength - offset - 2) + '" available');
      }
      if (maxEncodedParamLength < rLength) {
        throw new Error('"r" specified length of "' + rLength + '", max of "' + maxEncodedParamLength + '" is acceptable');
      }
      var rOffset = offset;
      offset += rLength;
      if (signature[offset++] !== ENCODED_TAG_INT) {
        throw new Error('Could not find expected "int" for "s"');
      }
      var sLength = signature[offset++];
      if (inputLength - offset !== sLength) {
        throw new Error('"s" specified length of "' + sLength + '", expected "' + (inputLength - offset) + '"');
      }
      if (maxEncodedParamLength < sLength) {
        throw new Error('"s" specified length of "' + sLength + '", max of "' + maxEncodedParamLength + '" is acceptable');
      }
      var sOffset = offset;
      offset += sLength;
      if (offset !== inputLength) {
        throw new Error('Expected to consume entire buffer, but "' + (inputLength - offset) + '" bytes remain');
      }
      var rPadding = paramBytes - rLength, sPadding = paramBytes - sLength;
      var dst = Buffer2.allocUnsafe(rPadding + rLength + sPadding + sLength);
      for (offset = 0; offset < rPadding; ++offset) {
        dst[offset] = 0;
      }
      signature.copy(dst, offset, rOffset + Math.max(-rPadding, 0), rOffset + rLength);
      offset = paramBytes;
      for (var o = offset; offset < o + sPadding; ++offset) {
        dst[offset] = 0;
      }
      signature.copy(dst, offset, sOffset + Math.max(-sPadding, 0), sOffset + sLength);
      dst = dst.toString("base64");
      dst = base64Url(dst);
      return dst;
    }
    function countPadding(buf, start, stop) {
      var padding = 0;
      while (start + padding < stop && buf[start + padding] === 0) {
        ++padding;
      }
      var needsSign = buf[start + padding] >= MAX_OCTET;
      if (needsSign) {
        --padding;
      }
      return padding;
    }
    function joseToDer(signature, alg) {
      signature = signatureAsBuffer(signature);
      var paramBytes = getParamBytesForAlg(alg);
      var signatureBytes = signature.length;
      if (signatureBytes !== paramBytes * 2) {
        throw new TypeError('"' + alg + '" signatures must be "' + paramBytes * 2 + '" bytes, saw "' + signatureBytes + '"');
      }
      var rPadding = countPadding(signature, 0, paramBytes);
      var sPadding = countPadding(signature, paramBytes, signature.length);
      var rLength = paramBytes - rPadding;
      var sLength = paramBytes - sPadding;
      var rsBytes = 1 + 1 + rLength + 1 + 1 + sLength;
      var shortLength = rsBytes < MAX_OCTET;
      var dst = Buffer2.allocUnsafe((shortLength ? 2 : 3) + rsBytes);
      var offset = 0;
      dst[offset++] = ENCODED_TAG_SEQ;
      if (shortLength) {
        dst[offset++] = rsBytes;
      } else {
        dst[offset++] = MAX_OCTET | 1;
        dst[offset++] = rsBytes & 255;
      }
      dst[offset++] = ENCODED_TAG_INT;
      dst[offset++] = rLength;
      if (rPadding < 0) {
        dst[offset++] = 0;
        offset += signature.copy(dst, offset, 0, paramBytes);
      } else {
        offset += signature.copy(dst, offset, rPadding, paramBytes);
      }
      dst[offset++] = ENCODED_TAG_INT;
      dst[offset++] = sLength;
      if (sPadding < 0) {
        dst[offset++] = 0;
        signature.copy(dst, offset, paramBytes);
      } else {
        signature.copy(dst, offset, paramBytes + sPadding);
      }
      return dst;
    }
    module2.exports = {
      derToJose,
      joseToDer
    };
  }
});

// node_modules/jwa/index.js
var require_jwa = __commonJS({
  "node_modules/jwa/index.js"(exports2, module2) {
    var bufferEqual = require_buffer_equal_constant_time();
    var Buffer2 = require_safe_buffer().Buffer;
    var crypto4 = require("crypto");
    var formatEcdsa = require_ecdsa_sig_formatter();
    var util = require("util");
    var MSG_INVALID_ALGORITHM = '"%s" is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".';
    var MSG_INVALID_SECRET = "secret must be a string or buffer";
    var MSG_INVALID_VERIFIER_KEY = "key must be a string or a buffer";
    var MSG_INVALID_SIGNER_KEY = "key must be a string, a buffer or an object";
    var supportsKeyObjects = typeof crypto4.createPublicKey === "function";
    if (supportsKeyObjects) {
      MSG_INVALID_VERIFIER_KEY += " or a KeyObject";
      MSG_INVALID_SECRET += "or a KeyObject";
    }
    function checkIsPublicKey(key) {
      if (Buffer2.isBuffer(key)) {
        return;
      }
      if (typeof key === "string") {
        return;
      }
      if (!supportsKeyObjects) {
        throw typeError(MSG_INVALID_VERIFIER_KEY);
      }
      if (typeof key !== "object") {
        throw typeError(MSG_INVALID_VERIFIER_KEY);
      }
      if (typeof key.type !== "string") {
        throw typeError(MSG_INVALID_VERIFIER_KEY);
      }
      if (typeof key.asymmetricKeyType !== "string") {
        throw typeError(MSG_INVALID_VERIFIER_KEY);
      }
      if (typeof key.export !== "function") {
        throw typeError(MSG_INVALID_VERIFIER_KEY);
      }
    }
    function checkIsPrivateKey(key) {
      if (Buffer2.isBuffer(key)) {
        return;
      }
      if (typeof key === "string") {
        return;
      }
      if (typeof key === "object") {
        return;
      }
      throw typeError(MSG_INVALID_SIGNER_KEY);
    }
    function checkIsSecretKey(key) {
      if (Buffer2.isBuffer(key)) {
        return;
      }
      if (typeof key === "string") {
        return key;
      }
      if (!supportsKeyObjects) {
        throw typeError(MSG_INVALID_SECRET);
      }
      if (typeof key !== "object") {
        throw typeError(MSG_INVALID_SECRET);
      }
      if (key.type !== "secret") {
        throw typeError(MSG_INVALID_SECRET);
      }
      if (typeof key.export !== "function") {
        throw typeError(MSG_INVALID_SECRET);
      }
    }
    function fromBase64(base64) {
      return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    }
    function toBase64(base64url) {
      base64url = base64url.toString();
      var padding = 4 - base64url.length % 4;
      if (padding !== 4) {
        for (var i = 0; i < padding; ++i) {
          base64url += "=";
        }
      }
      return base64url.replace(/\-/g, "+").replace(/_/g, "/");
    }
    function typeError(template) {
      var args = [].slice.call(arguments, 1);
      var errMsg = util.format.bind(util, template).apply(null, args);
      return new TypeError(errMsg);
    }
    function bufferOrString(obj) {
      return Buffer2.isBuffer(obj) || typeof obj === "string";
    }
    function normalizeInput(thing) {
      if (!bufferOrString(thing))
        thing = JSON.stringify(thing);
      return thing;
    }
    function createHmacSigner(bits) {
      return function sign(thing, secret) {
        checkIsSecretKey(secret);
        thing = normalizeInput(thing);
        var hmac = crypto4.createHmac("sha" + bits, secret);
        var sig = (hmac.update(thing), hmac.digest("base64"));
        return fromBase64(sig);
      };
    }
    function createHmacVerifier(bits) {
      return function verify(thing, signature, secret) {
        var computedSig = createHmacSigner(bits)(thing, secret);
        return bufferEqual(Buffer2.from(signature), Buffer2.from(computedSig));
      };
    }
    function createKeySigner(bits) {
      return function sign(thing, privateKey) {
        checkIsPrivateKey(privateKey);
        thing = normalizeInput(thing);
        var signer = crypto4.createSign("RSA-SHA" + bits);
        var sig = (signer.update(thing), signer.sign(privateKey, "base64"));
        return fromBase64(sig);
      };
    }
    function createKeyVerifier(bits) {
      return function verify(thing, signature, publicKey) {
        checkIsPublicKey(publicKey);
        thing = normalizeInput(thing);
        signature = toBase64(signature);
        var verifier = crypto4.createVerify("RSA-SHA" + bits);
        verifier.update(thing);
        return verifier.verify(publicKey, signature, "base64");
      };
    }
    function createPSSKeySigner(bits) {
      return function sign(thing, privateKey) {
        checkIsPrivateKey(privateKey);
        thing = normalizeInput(thing);
        var signer = crypto4.createSign("RSA-SHA" + bits);
        var sig = (signer.update(thing), signer.sign({
          key: privateKey,
          padding: crypto4.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto4.constants.RSA_PSS_SALTLEN_DIGEST
        }, "base64"));
        return fromBase64(sig);
      };
    }
    function createPSSKeyVerifier(bits) {
      return function verify(thing, signature, publicKey) {
        checkIsPublicKey(publicKey);
        thing = normalizeInput(thing);
        signature = toBase64(signature);
        var verifier = crypto4.createVerify("RSA-SHA" + bits);
        verifier.update(thing);
        return verifier.verify({
          key: publicKey,
          padding: crypto4.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: crypto4.constants.RSA_PSS_SALTLEN_DIGEST
        }, signature, "base64");
      };
    }
    function createECDSASigner(bits) {
      var inner = createKeySigner(bits);
      return function sign() {
        var signature = inner.apply(null, arguments);
        signature = formatEcdsa.derToJose(signature, "ES" + bits);
        return signature;
      };
    }
    function createECDSAVerifer(bits) {
      var inner = createKeyVerifier(bits);
      return function verify(thing, signature, publicKey) {
        signature = formatEcdsa.joseToDer(signature, "ES" + bits).toString("base64");
        var result = inner(thing, signature, publicKey);
        return result;
      };
    }
    function createNoneSigner() {
      return function sign() {
        return "";
      };
    }
    function createNoneVerifier() {
      return function verify(thing, signature) {
        return signature === "";
      };
    }
    module2.exports = function jwa(algorithm) {
      var signerFactories = {
        hs: createHmacSigner,
        rs: createKeySigner,
        ps: createPSSKeySigner,
        es: createECDSASigner,
        none: createNoneSigner
      };
      var verifierFactories = {
        hs: createHmacVerifier,
        rs: createKeyVerifier,
        ps: createPSSKeyVerifier,
        es: createECDSAVerifer,
        none: createNoneVerifier
      };
      var match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/i);
      if (!match)
        throw typeError(MSG_INVALID_ALGORITHM, algorithm);
      var algo = (match[1] || match[3]).toLowerCase();
      var bits = match[2];
      return {
        sign: signerFactories[algo](bits),
        verify: verifierFactories[algo](bits)
      };
    };
  }
});

// node_modules/jws/lib/tostring.js
var require_tostring = __commonJS({
  "node_modules/jws/lib/tostring.js"(exports2, module2) {
    var Buffer2 = require("buffer").Buffer;
    module2.exports = function toString(obj) {
      if (typeof obj === "string")
        return obj;
      if (typeof obj === "number" || Buffer2.isBuffer(obj))
        return obj.toString();
      return JSON.stringify(obj);
    };
  }
});

// node_modules/jws/lib/sign-stream.js
var require_sign_stream = __commonJS({
  "node_modules/jws/lib/sign-stream.js"(exports2, module2) {
    var Buffer2 = require_safe_buffer().Buffer;
    var DataStream = require_data_stream();
    var jwa = require_jwa();
    var Stream = require("stream");
    var toString = require_tostring();
    var util = require("util");
    function base64url(string, encoding) {
      return Buffer2.from(string, encoding).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    }
    function jwsSecuredInput(header, payload, encoding) {
      encoding = encoding || "utf8";
      var encodedHeader = base64url(toString(header), "binary");
      var encodedPayload = base64url(toString(payload), encoding);
      return util.format("%s.%s", encodedHeader, encodedPayload);
    }
    function jwsSign(opts) {
      var header = opts.header;
      var payload = opts.payload;
      var secretOrKey = opts.secret || opts.privateKey;
      var encoding = opts.encoding;
      var algo = jwa(header.alg);
      var securedInput = jwsSecuredInput(header, payload, encoding);
      var signature = algo.sign(securedInput, secretOrKey);
      return util.format("%s.%s", securedInput, signature);
    }
    function SignStream(opts) {
      var secret = opts.secret || opts.privateKey || opts.key;
      var secretStream = new DataStream(secret);
      this.readable = true;
      this.header = opts.header;
      this.encoding = opts.encoding;
      this.secret = this.privateKey = this.key = secretStream;
      this.payload = new DataStream(opts.payload);
      this.secret.once("close", function() {
        if (!this.payload.writable && this.readable)
          this.sign();
      }.bind(this));
      this.payload.once("close", function() {
        if (!this.secret.writable && this.readable)
          this.sign();
      }.bind(this));
    }
    util.inherits(SignStream, Stream);
    SignStream.prototype.sign = function sign() {
      try {
        var signature = jwsSign({
          header: this.header,
          payload: this.payload.buffer,
          secret: this.secret.buffer,
          encoding: this.encoding
        });
        this.emit("done", signature);
        this.emit("data", signature);
        this.emit("end");
        this.readable = false;
        return signature;
      } catch (e) {
        this.readable = false;
        this.emit("error", e);
        this.emit("close");
      }
    };
    SignStream.sign = jwsSign;
    module2.exports = SignStream;
  }
});

// node_modules/jws/lib/verify-stream.js
var require_verify_stream = __commonJS({
  "node_modules/jws/lib/verify-stream.js"(exports2, module2) {
    var Buffer2 = require_safe_buffer().Buffer;
    var DataStream = require_data_stream();
    var jwa = require_jwa();
    var Stream = require("stream");
    var toString = require_tostring();
    var util = require("util");
    var JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;
    function isObject(thing) {
      return Object.prototype.toString.call(thing) === "[object Object]";
    }
    function safeJsonParse(thing) {
      if (isObject(thing))
        return thing;
      try {
        return JSON.parse(thing);
      } catch (e) {
        return void 0;
      }
    }
    function headerFromJWS(jwsSig) {
      var encodedHeader = jwsSig.split(".", 1)[0];
      return safeJsonParse(Buffer2.from(encodedHeader, "base64").toString("binary"));
    }
    function securedInputFromJWS(jwsSig) {
      return jwsSig.split(".", 2).join(".");
    }
    function signatureFromJWS(jwsSig) {
      return jwsSig.split(".")[2];
    }
    function payloadFromJWS(jwsSig, encoding) {
      encoding = encoding || "utf8";
      var payload = jwsSig.split(".")[1];
      return Buffer2.from(payload, "base64").toString(encoding);
    }
    function isValidJws(string) {
      return JWS_REGEX.test(string) && !!headerFromJWS(string);
    }
    function jwsVerify(jwsSig, algorithm, secretOrKey) {
      if (!algorithm) {
        var err = new Error("Missing algorithm parameter for jws.verify");
        err.code = "MISSING_ALGORITHM";
        throw err;
      }
      jwsSig = toString(jwsSig);
      var signature = signatureFromJWS(jwsSig);
      var securedInput = securedInputFromJWS(jwsSig);
      var algo = jwa(algorithm);
      return algo.verify(securedInput, signature, secretOrKey);
    }
    function jwsDecode(jwsSig, opts) {
      opts = opts || {};
      jwsSig = toString(jwsSig);
      if (!isValidJws(jwsSig))
        return null;
      var header = headerFromJWS(jwsSig);
      if (!header)
        return null;
      var payload = payloadFromJWS(jwsSig);
      if (header.typ === "JWT" || opts.json)
        payload = JSON.parse(payload, opts.encoding);
      return {
        header,
        payload,
        signature: signatureFromJWS(jwsSig)
      };
    }
    function VerifyStream(opts) {
      opts = opts || {};
      var secretOrKey = opts.secret || opts.publicKey || opts.key;
      var secretStream = new DataStream(secretOrKey);
      this.readable = true;
      this.algorithm = opts.algorithm;
      this.encoding = opts.encoding;
      this.secret = this.publicKey = this.key = secretStream;
      this.signature = new DataStream(opts.signature);
      this.secret.once("close", function() {
        if (!this.signature.writable && this.readable)
          this.verify();
      }.bind(this));
      this.signature.once("close", function() {
        if (!this.secret.writable && this.readable)
          this.verify();
      }.bind(this));
    }
    util.inherits(VerifyStream, Stream);
    VerifyStream.prototype.verify = function verify() {
      try {
        var valid = jwsVerify(this.signature.buffer, this.algorithm, this.key.buffer);
        var obj = jwsDecode(this.signature.buffer, this.encoding);
        this.emit("done", valid, obj);
        this.emit("data", valid);
        this.emit("end");
        this.readable = false;
        return valid;
      } catch (e) {
        this.readable = false;
        this.emit("error", e);
        this.emit("close");
      }
    };
    VerifyStream.decode = jwsDecode;
    VerifyStream.isValid = isValidJws;
    VerifyStream.verify = jwsVerify;
    module2.exports = VerifyStream;
  }
});

// node_modules/jws/index.js
var require_jws = __commonJS({
  "node_modules/jws/index.js"(exports2) {
    var SignStream = require_sign_stream();
    var VerifyStream = require_verify_stream();
    var ALGORITHMS = [
      "HS256",
      "HS384",
      "HS512",
      "RS256",
      "RS384",
      "RS512",
      "PS256",
      "PS384",
      "PS512",
      "ES256",
      "ES384",
      "ES512"
    ];
    exports2.ALGORITHMS = ALGORITHMS;
    exports2.sign = SignStream.sign;
    exports2.verify = VerifyStream.verify;
    exports2.decode = VerifyStream.decode;
    exports2.isValid = VerifyStream.isValid;
    exports2.createSign = function createSign(opts) {
      return new SignStream(opts);
    };
    exports2.createVerify = function createVerify(opts) {
      return new VerifyStream(opts);
    };
  }
});

// node_modules/jsonwebtoken/decode.js
var require_decode = __commonJS({
  "node_modules/jsonwebtoken/decode.js"(exports2, module2) {
    var jws = require_jws();
    module2.exports = function(jwt, options) {
      options = options || {};
      var decoded = jws.decode(jwt, options);
      if (!decoded) {
        return null;
      }
      var payload = decoded.payload;
      if (typeof payload === "string") {
        try {
          var obj = JSON.parse(payload);
          if (obj !== null && typeof obj === "object") {
            payload = obj;
          }
        } catch (e) {
        }
      }
      if (options.complete === true) {
        return {
          header: decoded.header,
          payload,
          signature: decoded.signature
        };
      }
      return payload;
    };
  }
});

// node_modules/jsonwebtoken/lib/JsonWebTokenError.js
var require_JsonWebTokenError = __commonJS({
  "node_modules/jsonwebtoken/lib/JsonWebTokenError.js"(exports2, module2) {
    var JsonWebTokenError = function(message, error) {
      Error.call(this, message);
      if (Error.captureStackTrace) {
        Error.captureStackTrace(this, this.constructor);
      }
      this.name = "JsonWebTokenError";
      this.message = message;
      if (error)
        this.inner = error;
    };
    JsonWebTokenError.prototype = Object.create(Error.prototype);
    JsonWebTokenError.prototype.constructor = JsonWebTokenError;
    module2.exports = JsonWebTokenError;
  }
});

// node_modules/jsonwebtoken/lib/NotBeforeError.js
var require_NotBeforeError = __commonJS({
  "node_modules/jsonwebtoken/lib/NotBeforeError.js"(exports2, module2) {
    var JsonWebTokenError = require_JsonWebTokenError();
    var NotBeforeError = function(message, date) {
      JsonWebTokenError.call(this, message);
      this.name = "NotBeforeError";
      this.date = date;
    };
    NotBeforeError.prototype = Object.create(JsonWebTokenError.prototype);
    NotBeforeError.prototype.constructor = NotBeforeError;
    module2.exports = NotBeforeError;
  }
});

// node_modules/jsonwebtoken/lib/TokenExpiredError.js
var require_TokenExpiredError = __commonJS({
  "node_modules/jsonwebtoken/lib/TokenExpiredError.js"(exports2, module2) {
    var JsonWebTokenError = require_JsonWebTokenError();
    var TokenExpiredError = function(message, expiredAt) {
      JsonWebTokenError.call(this, message);
      this.name = "TokenExpiredError";
      this.expiredAt = expiredAt;
    };
    TokenExpiredError.prototype = Object.create(JsonWebTokenError.prototype);
    TokenExpiredError.prototype.constructor = TokenExpiredError;
    module2.exports = TokenExpiredError;
  }
});

// node_modules/ms/index.js
var require_ms = __commonJS({
  "node_modules/ms/index.js"(exports2, module2) {
    var s = 1e3;
    var m = s * 60;
    var h = m * 60;
    var d = h * 24;
    var w = d * 7;
    var y = d * 365.25;
    module2.exports = function(val, options) {
      options = options || {};
      var type = typeof val;
      if (type === "string" && val.length > 0) {
        return parse2(val);
      } else if (type === "number" && isFinite(val)) {
        return options.long ? fmtLong(val) : fmtShort(val);
      }
      throw new Error(
        "val is not a non-empty string or a valid number. val=" + JSON.stringify(val)
      );
    };
    function parse2(str) {
      str = String(str);
      if (str.length > 100) {
        return;
      }
      var match = /^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(
        str
      );
      if (!match) {
        return;
      }
      var n = parseFloat(match[1]);
      var type = (match[2] || "ms").toLowerCase();
      switch (type) {
        case "years":
        case "year":
        case "yrs":
        case "yr":
        case "y":
          return n * y;
        case "weeks":
        case "week":
        case "w":
          return n * w;
        case "days":
        case "day":
        case "d":
          return n * d;
        case "hours":
        case "hour":
        case "hrs":
        case "hr":
        case "h":
          return n * h;
        case "minutes":
        case "minute":
        case "mins":
        case "min":
        case "m":
          return n * m;
        case "seconds":
        case "second":
        case "secs":
        case "sec":
        case "s":
          return n * s;
        case "milliseconds":
        case "millisecond":
        case "msecs":
        case "msec":
        case "ms":
          return n;
        default:
          return void 0;
      }
    }
    function fmtShort(ms) {
      var msAbs = Math.abs(ms);
      if (msAbs >= d) {
        return Math.round(ms / d) + "d";
      }
      if (msAbs >= h) {
        return Math.round(ms / h) + "h";
      }
      if (msAbs >= m) {
        return Math.round(ms / m) + "m";
      }
      if (msAbs >= s) {
        return Math.round(ms / s) + "s";
      }
      return ms + "ms";
    }
    function fmtLong(ms) {
      var msAbs = Math.abs(ms);
      if (msAbs >= d) {
        return plural(ms, msAbs, d, "day");
      }
      if (msAbs >= h) {
        return plural(ms, msAbs, h, "hour");
      }
      if (msAbs >= m) {
        return plural(ms, msAbs, m, "minute");
      }
      if (msAbs >= s) {
        return plural(ms, msAbs, s, "second");
      }
      return ms + " ms";
    }
    function plural(ms, msAbs, n, name) {
      var isPlural = msAbs >= n * 1.5;
      return Math.round(ms / n) + " " + name + (isPlural ? "s" : "");
    }
  }
});

// node_modules/jsonwebtoken/lib/timespan.js
var require_timespan = __commonJS({
  "node_modules/jsonwebtoken/lib/timespan.js"(exports2, module2) {
    var ms = require_ms();
    module2.exports = function(time, iat) {
      var timestamp = iat || Math.floor(Date.now() / 1e3);
      if (typeof time === "string") {
        var milliseconds = ms(time);
        if (typeof milliseconds === "undefined") {
          return;
        }
        return Math.floor(timestamp + milliseconds / 1e3);
      } else if (typeof time === "number") {
        return timestamp + time;
      } else {
        return;
      }
    };
  }
});

// node_modules/semver/internal/constants.js
var require_constants = __commonJS({
  "node_modules/semver/internal/constants.js"(exports2, module2) {
    var SEMVER_SPEC_VERSION = "2.0.0";
    var MAX_LENGTH = 256;
    var MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER || /* istanbul ignore next */
    9007199254740991;
    var MAX_SAFE_COMPONENT_LENGTH = 16;
    var MAX_SAFE_BUILD_LENGTH = MAX_LENGTH - 6;
    var RELEASE_TYPES = [
      "major",
      "premajor",
      "minor",
      "preminor",
      "patch",
      "prepatch",
      "prerelease"
    ];
    module2.exports = {
      MAX_LENGTH,
      MAX_SAFE_COMPONENT_LENGTH,
      MAX_SAFE_BUILD_LENGTH,
      MAX_SAFE_INTEGER,
      RELEASE_TYPES,
      SEMVER_SPEC_VERSION,
      FLAG_INCLUDE_PRERELEASE: 1,
      FLAG_LOOSE: 2
    };
  }
});

// node_modules/semver/internal/debug.js
var require_debug = __commonJS({
  "node_modules/semver/internal/debug.js"(exports2, module2) {
    var debug2 = typeof process === "object" && process.env && process.env.NODE_DEBUG && /\bsemver\b/i.test(process.env.NODE_DEBUG) ? (...args) => console.error("SEMVER", ...args) : () => {
    };
    module2.exports = debug2;
  }
});

// node_modules/semver/internal/re.js
var require_re = __commonJS({
  "node_modules/semver/internal/re.js"(exports2, module2) {
    var {
      MAX_SAFE_COMPONENT_LENGTH,
      MAX_SAFE_BUILD_LENGTH,
      MAX_LENGTH
    } = require_constants();
    var debug2 = require_debug();
    exports2 = module2.exports = {};
    var re = exports2.re = [];
    var safeRe = exports2.safeRe = [];
    var src = exports2.src = [];
    var t = exports2.t = {};
    var R = 0;
    var LETTERDASHNUMBER = "[a-zA-Z0-9-]";
    var safeRegexReplacements = [
      ["\\s", 1],
      ["\\d", MAX_LENGTH],
      [LETTERDASHNUMBER, MAX_SAFE_BUILD_LENGTH]
    ];
    var makeSafeRegex = (value) => {
      for (const [token, max] of safeRegexReplacements) {
        value = value.split(`${token}*`).join(`${token}{0,${max}}`).split(`${token}+`).join(`${token}{1,${max}}`);
      }
      return value;
    };
    var createToken = (name, value, isGlobal) => {
      const safe = makeSafeRegex(value);
      const index = R++;
      debug2(name, index, value);
      t[name] = index;
      src[index] = value;
      re[index] = new RegExp(value, isGlobal ? "g" : void 0);
      safeRe[index] = new RegExp(safe, isGlobal ? "g" : void 0);
    };
    createToken("NUMERICIDENTIFIER", "0|[1-9]\\d*");
    createToken("NUMERICIDENTIFIERLOOSE", "\\d+");
    createToken("NONNUMERICIDENTIFIER", `\\d*[a-zA-Z-]${LETTERDASHNUMBER}*`);
    createToken("MAINVERSION", `(${src[t.NUMERICIDENTIFIER]})\\.(${src[t.NUMERICIDENTIFIER]})\\.(${src[t.NUMERICIDENTIFIER]})`);
    createToken("MAINVERSIONLOOSE", `(${src[t.NUMERICIDENTIFIERLOOSE]})\\.(${src[t.NUMERICIDENTIFIERLOOSE]})\\.(${src[t.NUMERICIDENTIFIERLOOSE]})`);
    createToken("PRERELEASEIDENTIFIER", `(?:${src[t.NUMERICIDENTIFIER]}|${src[t.NONNUMERICIDENTIFIER]})`);
    createToken("PRERELEASEIDENTIFIERLOOSE", `(?:${src[t.NUMERICIDENTIFIERLOOSE]}|${src[t.NONNUMERICIDENTIFIER]})`);
    createToken("PRERELEASE", `(?:-(${src[t.PRERELEASEIDENTIFIER]}(?:\\.${src[t.PRERELEASEIDENTIFIER]})*))`);
    createToken("PRERELEASELOOSE", `(?:-?(${src[t.PRERELEASEIDENTIFIERLOOSE]}(?:\\.${src[t.PRERELEASEIDENTIFIERLOOSE]})*))`);
    createToken("BUILDIDENTIFIER", `${LETTERDASHNUMBER}+`);
    createToken("BUILD", `(?:\\+(${src[t.BUILDIDENTIFIER]}(?:\\.${src[t.BUILDIDENTIFIER]})*))`);
    createToken("FULLPLAIN", `v?${src[t.MAINVERSION]}${src[t.PRERELEASE]}?${src[t.BUILD]}?`);
    createToken("FULL", `^${src[t.FULLPLAIN]}$`);
    createToken("LOOSEPLAIN", `[v=\\s]*${src[t.MAINVERSIONLOOSE]}${src[t.PRERELEASELOOSE]}?${src[t.BUILD]}?`);
    createToken("LOOSE", `^${src[t.LOOSEPLAIN]}$`);
    createToken("GTLT", "((?:<|>)?=?)");
    createToken("XRANGEIDENTIFIERLOOSE", `${src[t.NUMERICIDENTIFIERLOOSE]}|x|X|\\*`);
    createToken("XRANGEIDENTIFIER", `${src[t.NUMERICIDENTIFIER]}|x|X|\\*`);
    createToken("XRANGEPLAIN", `[v=\\s]*(${src[t.XRANGEIDENTIFIER]})(?:\\.(${src[t.XRANGEIDENTIFIER]})(?:\\.(${src[t.XRANGEIDENTIFIER]})(?:${src[t.PRERELEASE]})?${src[t.BUILD]}?)?)?`);
    createToken("XRANGEPLAINLOOSE", `[v=\\s]*(${src[t.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t.XRANGEIDENTIFIERLOOSE]})(?:\\.(${src[t.XRANGEIDENTIFIERLOOSE]})(?:${src[t.PRERELEASELOOSE]})?${src[t.BUILD]}?)?)?`);
    createToken("XRANGE", `^${src[t.GTLT]}\\s*${src[t.XRANGEPLAIN]}$`);
    createToken("XRANGELOOSE", `^${src[t.GTLT]}\\s*${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("COERCE", `${"(^|[^\\d])(\\d{1,"}${MAX_SAFE_COMPONENT_LENGTH}})(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH}}))?(?:\\.(\\d{1,${MAX_SAFE_COMPONENT_LENGTH}}))?(?:$|[^\\d])`);
    createToken("COERCERTL", src[t.COERCE], true);
    createToken("LONETILDE", "(?:~>?)");
    createToken("TILDETRIM", `(\\s*)${src[t.LONETILDE]}\\s+`, true);
    exports2.tildeTrimReplace = "$1~";
    createToken("TILDE", `^${src[t.LONETILDE]}${src[t.XRANGEPLAIN]}$`);
    createToken("TILDELOOSE", `^${src[t.LONETILDE]}${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("LONECARET", "(?:\\^)");
    createToken("CARETTRIM", `(\\s*)${src[t.LONECARET]}\\s+`, true);
    exports2.caretTrimReplace = "$1^";
    createToken("CARET", `^${src[t.LONECARET]}${src[t.XRANGEPLAIN]}$`);
    createToken("CARETLOOSE", `^${src[t.LONECARET]}${src[t.XRANGEPLAINLOOSE]}$`);
    createToken("COMPARATORLOOSE", `^${src[t.GTLT]}\\s*(${src[t.LOOSEPLAIN]})$|^$`);
    createToken("COMPARATOR", `^${src[t.GTLT]}\\s*(${src[t.FULLPLAIN]})$|^$`);
    createToken("COMPARATORTRIM", `(\\s*)${src[t.GTLT]}\\s*(${src[t.LOOSEPLAIN]}|${src[t.XRANGEPLAIN]})`, true);
    exports2.comparatorTrimReplace = "$1$2$3";
    createToken("HYPHENRANGE", `^\\s*(${src[t.XRANGEPLAIN]})\\s+-\\s+(${src[t.XRANGEPLAIN]})\\s*$`);
    createToken("HYPHENRANGELOOSE", `^\\s*(${src[t.XRANGEPLAINLOOSE]})\\s+-\\s+(${src[t.XRANGEPLAINLOOSE]})\\s*$`);
    createToken("STAR", "(<|>)?=?\\s*\\*");
    createToken("GTE0", "^\\s*>=\\s*0\\.0\\.0\\s*$");
    createToken("GTE0PRE", "^\\s*>=\\s*0\\.0\\.0-0\\s*$");
  }
});

// node_modules/semver/internal/parse-options.js
var require_parse_options = __commonJS({
  "node_modules/semver/internal/parse-options.js"(exports2, module2) {
    var looseOption = Object.freeze({ loose: true });
    var emptyOpts = Object.freeze({});
    var parseOptions = (options) => {
      if (!options) {
        return emptyOpts;
      }
      if (typeof options !== "object") {
        return looseOption;
      }
      return options;
    };
    module2.exports = parseOptions;
  }
});

// node_modules/semver/internal/identifiers.js
var require_identifiers = __commonJS({
  "node_modules/semver/internal/identifiers.js"(exports2, module2) {
    var numeric = /^[0-9]+$/;
    var compareIdentifiers = (a, b) => {
      const anum = numeric.test(a);
      const bnum = numeric.test(b);
      if (anum && bnum) {
        a = +a;
        b = +b;
      }
      return a === b ? 0 : anum && !bnum ? -1 : bnum && !anum ? 1 : a < b ? -1 : 1;
    };
    var rcompareIdentifiers = (a, b) => compareIdentifiers(b, a);
    module2.exports = {
      compareIdentifiers,
      rcompareIdentifiers
    };
  }
});

// node_modules/semver/classes/semver.js
var require_semver = __commonJS({
  "node_modules/semver/classes/semver.js"(exports2, module2) {
    var debug2 = require_debug();
    var { MAX_LENGTH, MAX_SAFE_INTEGER } = require_constants();
    var { safeRe: re, t } = require_re();
    var parseOptions = require_parse_options();
    var { compareIdentifiers } = require_identifiers();
    var SemVer = class _SemVer {
      constructor(version2, options) {
        options = parseOptions(options);
        if (version2 instanceof _SemVer) {
          if (version2.loose === !!options.loose && version2.includePrerelease === !!options.includePrerelease) {
            return version2;
          } else {
            version2 = version2.version;
          }
        } else if (typeof version2 !== "string") {
          throw new TypeError(`Invalid version. Must be a string. Got type "${typeof version2}".`);
        }
        if (version2.length > MAX_LENGTH) {
          throw new TypeError(
            `version is longer than ${MAX_LENGTH} characters`
          );
        }
        debug2("SemVer", version2, options);
        this.options = options;
        this.loose = !!options.loose;
        this.includePrerelease = !!options.includePrerelease;
        const m = version2.trim().match(options.loose ? re[t.LOOSE] : re[t.FULL]);
        if (!m) {
          throw new TypeError(`Invalid Version: ${version2}`);
        }
        this.raw = version2;
        this.major = +m[1];
        this.minor = +m[2];
        this.patch = +m[3];
        if (this.major > MAX_SAFE_INTEGER || this.major < 0) {
          throw new TypeError("Invalid major version");
        }
        if (this.minor > MAX_SAFE_INTEGER || this.minor < 0) {
          throw new TypeError("Invalid minor version");
        }
        if (this.patch > MAX_SAFE_INTEGER || this.patch < 0) {
          throw new TypeError("Invalid patch version");
        }
        if (!m[4]) {
          this.prerelease = [];
        } else {
          this.prerelease = m[4].split(".").map((id) => {
            if (/^[0-9]+$/.test(id)) {
              const num = +id;
              if (num >= 0 && num < MAX_SAFE_INTEGER) {
                return num;
              }
            }
            return id;
          });
        }
        this.build = m[5] ? m[5].split(".") : [];
        this.format();
      }
      format() {
        this.version = `${this.major}.${this.minor}.${this.patch}`;
        if (this.prerelease.length) {
          this.version += `-${this.prerelease.join(".")}`;
        }
        return this.version;
      }
      toString() {
        return this.version;
      }
      compare(other) {
        debug2("SemVer.compare", this.version, this.options, other);
        if (!(other instanceof _SemVer)) {
          if (typeof other === "string" && other === this.version) {
            return 0;
          }
          other = new _SemVer(other, this.options);
        }
        if (other.version === this.version) {
          return 0;
        }
        return this.compareMain(other) || this.comparePre(other);
      }
      compareMain(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        return compareIdentifiers(this.major, other.major) || compareIdentifiers(this.minor, other.minor) || compareIdentifiers(this.patch, other.patch);
      }
      comparePre(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        if (this.prerelease.length && !other.prerelease.length) {
          return -1;
        } else if (!this.prerelease.length && other.prerelease.length) {
          return 1;
        } else if (!this.prerelease.length && !other.prerelease.length) {
          return 0;
        }
        let i = 0;
        do {
          const a = this.prerelease[i];
          const b = other.prerelease[i];
          debug2("prerelease compare", i, a, b);
          if (a === void 0 && b === void 0) {
            return 0;
          } else if (b === void 0) {
            return 1;
          } else if (a === void 0) {
            return -1;
          } else if (a === b) {
            continue;
          } else {
            return compareIdentifiers(a, b);
          }
        } while (++i);
      }
      compareBuild(other) {
        if (!(other instanceof _SemVer)) {
          other = new _SemVer(other, this.options);
        }
        let i = 0;
        do {
          const a = this.build[i];
          const b = other.build[i];
          debug2("prerelease compare", i, a, b);
          if (a === void 0 && b === void 0) {
            return 0;
          } else if (b === void 0) {
            return 1;
          } else if (a === void 0) {
            return -1;
          } else if (a === b) {
            continue;
          } else {
            return compareIdentifiers(a, b);
          }
        } while (++i);
      }
      // preminor will bump the version up to the next minor release, and immediately
      // down to pre-release. premajor and prepatch work the same way.
      inc(release, identifier, identifierBase) {
        switch (release) {
          case "premajor":
            this.prerelease.length = 0;
            this.patch = 0;
            this.minor = 0;
            this.major++;
            this.inc("pre", identifier, identifierBase);
            break;
          case "preminor":
            this.prerelease.length = 0;
            this.patch = 0;
            this.minor++;
            this.inc("pre", identifier, identifierBase);
            break;
          case "prepatch":
            this.prerelease.length = 0;
            this.inc("patch", identifier, identifierBase);
            this.inc("pre", identifier, identifierBase);
            break;
          case "prerelease":
            if (this.prerelease.length === 0) {
              this.inc("patch", identifier, identifierBase);
            }
            this.inc("pre", identifier, identifierBase);
            break;
          case "major":
            if (this.minor !== 0 || this.patch !== 0 || this.prerelease.length === 0) {
              this.major++;
            }
            this.minor = 0;
            this.patch = 0;
            this.prerelease = [];
            break;
          case "minor":
            if (this.patch !== 0 || this.prerelease.length === 0) {
              this.minor++;
            }
            this.patch = 0;
            this.prerelease = [];
            break;
          case "patch":
            if (this.prerelease.length === 0) {
              this.patch++;
            }
            this.prerelease = [];
            break;
          case "pre": {
            const base = Number(identifierBase) ? 1 : 0;
            if (!identifier && identifierBase === false) {
              throw new Error("invalid increment argument: identifier is empty");
            }
            if (this.prerelease.length === 0) {
              this.prerelease = [base];
            } else {
              let i = this.prerelease.length;
              while (--i >= 0) {
                if (typeof this.prerelease[i] === "number") {
                  this.prerelease[i]++;
                  i = -2;
                }
              }
              if (i === -1) {
                if (identifier === this.prerelease.join(".") && identifierBase === false) {
                  throw new Error("invalid increment argument: identifier already exists");
                }
                this.prerelease.push(base);
              }
            }
            if (identifier) {
              let prerelease = [identifier, base];
              if (identifierBase === false) {
                prerelease = [identifier];
              }
              if (compareIdentifiers(this.prerelease[0], identifier) === 0) {
                if (isNaN(this.prerelease[1])) {
                  this.prerelease = prerelease;
                }
              } else {
                this.prerelease = prerelease;
              }
            }
            break;
          }
          default:
            throw new Error(`invalid increment argument: ${release}`);
        }
        this.raw = this.format();
        if (this.build.length) {
          this.raw += `+${this.build.join(".")}`;
        }
        return this;
      }
    };
    module2.exports = SemVer;
  }
});

// node_modules/semver/functions/parse.js
var require_parse = __commonJS({
  "node_modules/semver/functions/parse.js"(exports2, module2) {
    var SemVer = require_semver();
    var parse2 = (version2, options, throwErrors = false) => {
      if (version2 instanceof SemVer) {
        return version2;
      }
      try {
        return new SemVer(version2, options);
      } catch (er) {
        if (!throwErrors) {
          return null;
        }
        throw er;
      }
    };
    module2.exports = parse2;
  }
});

// node_modules/semver/functions/valid.js
var require_valid = __commonJS({
  "node_modules/semver/functions/valid.js"(exports2, module2) {
    var parse2 = require_parse();
    var valid = (version2, options) => {
      const v = parse2(version2, options);
      return v ? v.version : null;
    };
    module2.exports = valid;
  }
});

// node_modules/semver/functions/clean.js
var require_clean = __commonJS({
  "node_modules/semver/functions/clean.js"(exports2, module2) {
    var parse2 = require_parse();
    var clean = (version2, options) => {
      const s = parse2(version2.trim().replace(/^[=v]+/, ""), options);
      return s ? s.version : null;
    };
    module2.exports = clean;
  }
});

// node_modules/semver/functions/inc.js
var require_inc = __commonJS({
  "node_modules/semver/functions/inc.js"(exports2, module2) {
    var SemVer = require_semver();
    var inc = (version2, release, options, identifier, identifierBase) => {
      if (typeof options === "string") {
        identifierBase = identifier;
        identifier = options;
        options = void 0;
      }
      try {
        return new SemVer(
          version2 instanceof SemVer ? version2.version : version2,
          options
        ).inc(release, identifier, identifierBase).version;
      } catch (er) {
        return null;
      }
    };
    module2.exports = inc;
  }
});

// node_modules/semver/functions/diff.js
var require_diff = __commonJS({
  "node_modules/semver/functions/diff.js"(exports2, module2) {
    var parse2 = require_parse();
    var diff = (version1, version2) => {
      const v12 = parse2(version1, null, true);
      const v2 = parse2(version2, null, true);
      const comparison = v12.compare(v2);
      if (comparison === 0) {
        return null;
      }
      const v1Higher = comparison > 0;
      const highVersion = v1Higher ? v12 : v2;
      const lowVersion = v1Higher ? v2 : v12;
      const highHasPre = !!highVersion.prerelease.length;
      const lowHasPre = !!lowVersion.prerelease.length;
      if (lowHasPre && !highHasPre) {
        if (!lowVersion.patch && !lowVersion.minor) {
          return "major";
        }
        if (highVersion.patch) {
          return "patch";
        }
        if (highVersion.minor) {
          return "minor";
        }
        return "major";
      }
      const prefix = highHasPre ? "pre" : "";
      if (v12.major !== v2.major) {
        return prefix + "major";
      }
      if (v12.minor !== v2.minor) {
        return prefix + "minor";
      }
      if (v12.patch !== v2.patch) {
        return prefix + "patch";
      }
      return "prerelease";
    };
    module2.exports = diff;
  }
});

// node_modules/semver/functions/major.js
var require_major = __commonJS({
  "node_modules/semver/functions/major.js"(exports2, module2) {
    var SemVer = require_semver();
    var major = (a, loose) => new SemVer(a, loose).major;
    module2.exports = major;
  }
});

// node_modules/semver/functions/minor.js
var require_minor = __commonJS({
  "node_modules/semver/functions/minor.js"(exports2, module2) {
    var SemVer = require_semver();
    var minor = (a, loose) => new SemVer(a, loose).minor;
    module2.exports = minor;
  }
});

// node_modules/semver/functions/patch.js
var require_patch = __commonJS({
  "node_modules/semver/functions/patch.js"(exports2, module2) {
    var SemVer = require_semver();
    var patch = (a, loose) => new SemVer(a, loose).patch;
    module2.exports = patch;
  }
});

// node_modules/semver/functions/prerelease.js
var require_prerelease = __commonJS({
  "node_modules/semver/functions/prerelease.js"(exports2, module2) {
    var parse2 = require_parse();
    var prerelease = (version2, options) => {
      const parsed = parse2(version2, options);
      return parsed && parsed.prerelease.length ? parsed.prerelease : null;
    };
    module2.exports = prerelease;
  }
});

// node_modules/semver/functions/compare.js
var require_compare = __commonJS({
  "node_modules/semver/functions/compare.js"(exports2, module2) {
    var SemVer = require_semver();
    var compare = (a, b, loose) => new SemVer(a, loose).compare(new SemVer(b, loose));
    module2.exports = compare;
  }
});

// node_modules/semver/functions/rcompare.js
var require_rcompare = __commonJS({
  "node_modules/semver/functions/rcompare.js"(exports2, module2) {
    var compare = require_compare();
    var rcompare = (a, b, loose) => compare(b, a, loose);
    module2.exports = rcompare;
  }
});

// node_modules/semver/functions/compare-loose.js
var require_compare_loose = __commonJS({
  "node_modules/semver/functions/compare-loose.js"(exports2, module2) {
    var compare = require_compare();
    var compareLoose = (a, b) => compare(a, b, true);
    module2.exports = compareLoose;
  }
});

// node_modules/semver/functions/compare-build.js
var require_compare_build = __commonJS({
  "node_modules/semver/functions/compare-build.js"(exports2, module2) {
    var SemVer = require_semver();
    var compareBuild = (a, b, loose) => {
      const versionA = new SemVer(a, loose);
      const versionB = new SemVer(b, loose);
      return versionA.compare(versionB) || versionA.compareBuild(versionB);
    };
    module2.exports = compareBuild;
  }
});

// node_modules/semver/functions/sort.js
var require_sort = __commonJS({
  "node_modules/semver/functions/sort.js"(exports2, module2) {
    var compareBuild = require_compare_build();
    var sort = (list, loose) => list.sort((a, b) => compareBuild(a, b, loose));
    module2.exports = sort;
  }
});

// node_modules/semver/functions/rsort.js
var require_rsort = __commonJS({
  "node_modules/semver/functions/rsort.js"(exports2, module2) {
    var compareBuild = require_compare_build();
    var rsort = (list, loose) => list.sort((a, b) => compareBuild(b, a, loose));
    module2.exports = rsort;
  }
});

// node_modules/semver/functions/gt.js
var require_gt = __commonJS({
  "node_modules/semver/functions/gt.js"(exports2, module2) {
    var compare = require_compare();
    var gt = (a, b, loose) => compare(a, b, loose) > 0;
    module2.exports = gt;
  }
});

// node_modules/semver/functions/lt.js
var require_lt = __commonJS({
  "node_modules/semver/functions/lt.js"(exports2, module2) {
    var compare = require_compare();
    var lt = (a, b, loose) => compare(a, b, loose) < 0;
    module2.exports = lt;
  }
});

// node_modules/semver/functions/eq.js
var require_eq = __commonJS({
  "node_modules/semver/functions/eq.js"(exports2, module2) {
    var compare = require_compare();
    var eq = (a, b, loose) => compare(a, b, loose) === 0;
    module2.exports = eq;
  }
});

// node_modules/semver/functions/neq.js
var require_neq = __commonJS({
  "node_modules/semver/functions/neq.js"(exports2, module2) {
    var compare = require_compare();
    var neq = (a, b, loose) => compare(a, b, loose) !== 0;
    module2.exports = neq;
  }
});

// node_modules/semver/functions/gte.js
var require_gte = __commonJS({
  "node_modules/semver/functions/gte.js"(exports2, module2) {
    var compare = require_compare();
    var gte = (a, b, loose) => compare(a, b, loose) >= 0;
    module2.exports = gte;
  }
});

// node_modules/semver/functions/lte.js
var require_lte = __commonJS({
  "node_modules/semver/functions/lte.js"(exports2, module2) {
    var compare = require_compare();
    var lte = (a, b, loose) => compare(a, b, loose) <= 0;
    module2.exports = lte;
  }
});

// node_modules/semver/functions/cmp.js
var require_cmp = __commonJS({
  "node_modules/semver/functions/cmp.js"(exports2, module2) {
    var eq = require_eq();
    var neq = require_neq();
    var gt = require_gt();
    var gte = require_gte();
    var lt = require_lt();
    var lte = require_lte();
    var cmp = (a, op, b, loose) => {
      switch (op) {
        case "===":
          if (typeof a === "object") {
            a = a.version;
          }
          if (typeof b === "object") {
            b = b.version;
          }
          return a === b;
        case "!==":
          if (typeof a === "object") {
            a = a.version;
          }
          if (typeof b === "object") {
            b = b.version;
          }
          return a !== b;
        case "":
        case "=":
        case "==":
          return eq(a, b, loose);
        case "!=":
          return neq(a, b, loose);
        case ">":
          return gt(a, b, loose);
        case ">=":
          return gte(a, b, loose);
        case "<":
          return lt(a, b, loose);
        case "<=":
          return lte(a, b, loose);
        default:
          throw new TypeError(`Invalid operator: ${op}`);
      }
    };
    module2.exports = cmp;
  }
});

// node_modules/semver/functions/coerce.js
var require_coerce = __commonJS({
  "node_modules/semver/functions/coerce.js"(exports2, module2) {
    var SemVer = require_semver();
    var parse2 = require_parse();
    var { safeRe: re, t } = require_re();
    var coerce = (version2, options) => {
      if (version2 instanceof SemVer) {
        return version2;
      }
      if (typeof version2 === "number") {
        version2 = String(version2);
      }
      if (typeof version2 !== "string") {
        return null;
      }
      options = options || {};
      let match = null;
      if (!options.rtl) {
        match = version2.match(re[t.COERCE]);
      } else {
        let next;
        while ((next = re[t.COERCERTL].exec(version2)) && (!match || match.index + match[0].length !== version2.length)) {
          if (!match || next.index + next[0].length !== match.index + match[0].length) {
            match = next;
          }
          re[t.COERCERTL].lastIndex = next.index + next[1].length + next[2].length;
        }
        re[t.COERCERTL].lastIndex = -1;
      }
      if (match === null) {
        return null;
      }
      return parse2(`${match[2]}.${match[3] || "0"}.${match[4] || "0"}`, options);
    };
    module2.exports = coerce;
  }
});

// node_modules/yallist/iterator.js
var require_iterator = __commonJS({
  "node_modules/yallist/iterator.js"(exports2, module2) {
    "use strict";
    module2.exports = function(Yallist) {
      Yallist.prototype[Symbol.iterator] = function* () {
        for (let walker = this.head; walker; walker = walker.next) {
          yield walker.value;
        }
      };
    };
  }
});

// node_modules/yallist/yallist.js
var require_yallist = __commonJS({
  "node_modules/yallist/yallist.js"(exports2, module2) {
    "use strict";
    module2.exports = Yallist;
    Yallist.Node = Node;
    Yallist.create = Yallist;
    function Yallist(list) {
      var self2 = this;
      if (!(self2 instanceof Yallist)) {
        self2 = new Yallist();
      }
      self2.tail = null;
      self2.head = null;
      self2.length = 0;
      if (list && typeof list.forEach === "function") {
        list.forEach(function(item) {
          self2.push(item);
        });
      } else if (arguments.length > 0) {
        for (var i = 0, l = arguments.length; i < l; i++) {
          self2.push(arguments[i]);
        }
      }
      return self2;
    }
    Yallist.prototype.removeNode = function(node) {
      if (node.list !== this) {
        throw new Error("removing node which does not belong to this list");
      }
      var next = node.next;
      var prev = node.prev;
      if (next) {
        next.prev = prev;
      }
      if (prev) {
        prev.next = next;
      }
      if (node === this.head) {
        this.head = next;
      }
      if (node === this.tail) {
        this.tail = prev;
      }
      node.list.length--;
      node.next = null;
      node.prev = null;
      node.list = null;
      return next;
    };
    Yallist.prototype.unshiftNode = function(node) {
      if (node === this.head) {
        return;
      }
      if (node.list) {
        node.list.removeNode(node);
      }
      var head = this.head;
      node.list = this;
      node.next = head;
      if (head) {
        head.prev = node;
      }
      this.head = node;
      if (!this.tail) {
        this.tail = node;
      }
      this.length++;
    };
    Yallist.prototype.pushNode = function(node) {
      if (node === this.tail) {
        return;
      }
      if (node.list) {
        node.list.removeNode(node);
      }
      var tail = this.tail;
      node.list = this;
      node.prev = tail;
      if (tail) {
        tail.next = node;
      }
      this.tail = node;
      if (!this.head) {
        this.head = node;
      }
      this.length++;
    };
    Yallist.prototype.push = function() {
      for (var i = 0, l = arguments.length; i < l; i++) {
        push(this, arguments[i]);
      }
      return this.length;
    };
    Yallist.prototype.unshift = function() {
      for (var i = 0, l = arguments.length; i < l; i++) {
        unshift(this, arguments[i]);
      }
      return this.length;
    };
    Yallist.prototype.pop = function() {
      if (!this.tail) {
        return void 0;
      }
      var res = this.tail.value;
      this.tail = this.tail.prev;
      if (this.tail) {
        this.tail.next = null;
      } else {
        this.head = null;
      }
      this.length--;
      return res;
    };
    Yallist.prototype.shift = function() {
      if (!this.head) {
        return void 0;
      }
      var res = this.head.value;
      this.head = this.head.next;
      if (this.head) {
        this.head.prev = null;
      } else {
        this.tail = null;
      }
      this.length--;
      return res;
    };
    Yallist.prototype.forEach = function(fn, thisp) {
      thisp = thisp || this;
      for (var walker = this.head, i = 0; walker !== null; i++) {
        fn.call(thisp, walker.value, i, this);
        walker = walker.next;
      }
    };
    Yallist.prototype.forEachReverse = function(fn, thisp) {
      thisp = thisp || this;
      for (var walker = this.tail, i = this.length - 1; walker !== null; i--) {
        fn.call(thisp, walker.value, i, this);
        walker = walker.prev;
      }
    };
    Yallist.prototype.get = function(n) {
      for (var i = 0, walker = this.head; walker !== null && i < n; i++) {
        walker = walker.next;
      }
      if (i === n && walker !== null) {
        return walker.value;
      }
    };
    Yallist.prototype.getReverse = function(n) {
      for (var i = 0, walker = this.tail; walker !== null && i < n; i++) {
        walker = walker.prev;
      }
      if (i === n && walker !== null) {
        return walker.value;
      }
    };
    Yallist.prototype.map = function(fn, thisp) {
      thisp = thisp || this;
      var res = new Yallist();
      for (var walker = this.head; walker !== null; ) {
        res.push(fn.call(thisp, walker.value, this));
        walker = walker.next;
      }
      return res;
    };
    Yallist.prototype.mapReverse = function(fn, thisp) {
      thisp = thisp || this;
      var res = new Yallist();
      for (var walker = this.tail; walker !== null; ) {
        res.push(fn.call(thisp, walker.value, this));
        walker = walker.prev;
      }
      return res;
    };
    Yallist.prototype.reduce = function(fn, initial) {
      var acc;
      var walker = this.head;
      if (arguments.length > 1) {
        acc = initial;
      } else if (this.head) {
        walker = this.head.next;
        acc = this.head.value;
      } else {
        throw new TypeError("Reduce of empty list with no initial value");
      }
      for (var i = 0; walker !== null; i++) {
        acc = fn(acc, walker.value, i);
        walker = walker.next;
      }
      return acc;
    };
    Yallist.prototype.reduceReverse = function(fn, initial) {
      var acc;
      var walker = this.tail;
      if (arguments.length > 1) {
        acc = initial;
      } else if (this.tail) {
        walker = this.tail.prev;
        acc = this.tail.value;
      } else {
        throw new TypeError("Reduce of empty list with no initial value");
      }
      for (var i = this.length - 1; walker !== null; i--) {
        acc = fn(acc, walker.value, i);
        walker = walker.prev;
      }
      return acc;
    };
    Yallist.prototype.toArray = function() {
      var arr = new Array(this.length);
      for (var i = 0, walker = this.head; walker !== null; i++) {
        arr[i] = walker.value;
        walker = walker.next;
      }
      return arr;
    };
    Yallist.prototype.toArrayReverse = function() {
      var arr = new Array(this.length);
      for (var i = 0, walker = this.tail; walker !== null; i++) {
        arr[i] = walker.value;
        walker = walker.prev;
      }
      return arr;
    };
    Yallist.prototype.slice = function(from, to) {
      to = to || this.length;
      if (to < 0) {
        to += this.length;
      }
      from = from || 0;
      if (from < 0) {
        from += this.length;
      }
      var ret = new Yallist();
      if (to < from || to < 0) {
        return ret;
      }
      if (from < 0) {
        from = 0;
      }
      if (to > this.length) {
        to = this.length;
      }
      for (var i = 0, walker = this.head; walker !== null && i < from; i++) {
        walker = walker.next;
      }
      for (; walker !== null && i < to; i++, walker = walker.next) {
        ret.push(walker.value);
      }
      return ret;
    };
    Yallist.prototype.sliceReverse = function(from, to) {
      to = to || this.length;
      if (to < 0) {
        to += this.length;
      }
      from = from || 0;
      if (from < 0) {
        from += this.length;
      }
      var ret = new Yallist();
      if (to < from || to < 0) {
        return ret;
      }
      if (from < 0) {
        from = 0;
      }
      if (to > this.length) {
        to = this.length;
      }
      for (var i = this.length, walker = this.tail; walker !== null && i > to; i--) {
        walker = walker.prev;
      }
      for (; walker !== null && i > from; i--, walker = walker.prev) {
        ret.push(walker.value);
      }
      return ret;
    };
    Yallist.prototype.splice = function(start, deleteCount, ...nodes) {
      if (start > this.length) {
        start = this.length - 1;
      }
      if (start < 0) {
        start = this.length + start;
      }
      for (var i = 0, walker = this.head; walker !== null && i < start; i++) {
        walker = walker.next;
      }
      var ret = [];
      for (var i = 0; walker && i < deleteCount; i++) {
        ret.push(walker.value);
        walker = this.removeNode(walker);
      }
      if (walker === null) {
        walker = this.tail;
      }
      if (walker !== this.head && walker !== this.tail) {
        walker = walker.prev;
      }
      for (var i = 0; i < nodes.length; i++) {
        walker = insert(this, walker, nodes[i]);
      }
      return ret;
    };
    Yallist.prototype.reverse = function() {
      var head = this.head;
      var tail = this.tail;
      for (var walker = head; walker !== null; walker = walker.prev) {
        var p = walker.prev;
        walker.prev = walker.next;
        walker.next = p;
      }
      this.head = tail;
      this.tail = head;
      return this;
    };
    function insert(self2, node, value) {
      var inserted = node === self2.head ? new Node(value, null, node, self2) : new Node(value, node, node.next, self2);
      if (inserted.next === null) {
        self2.tail = inserted;
      }
      if (inserted.prev === null) {
        self2.head = inserted;
      }
      self2.length++;
      return inserted;
    }
    function push(self2, item) {
      self2.tail = new Node(item, self2.tail, null, self2);
      if (!self2.head) {
        self2.head = self2.tail;
      }
      self2.length++;
    }
    function unshift(self2, item) {
      self2.head = new Node(item, null, self2.head, self2);
      if (!self2.tail) {
        self2.tail = self2.head;
      }
      self2.length++;
    }
    function Node(value, prev, next, list) {
      if (!(this instanceof Node)) {
        return new Node(value, prev, next, list);
      }
      this.list = list;
      this.value = value;
      if (prev) {
        prev.next = this;
        this.prev = prev;
      } else {
        this.prev = null;
      }
      if (next) {
        next.prev = this;
        this.next = next;
      } else {
        this.next = null;
      }
    }
    try {
      require_iterator()(Yallist);
    } catch (er) {
    }
  }
});

// node_modules/lru-cache/index.js
var require_lru_cache = __commonJS({
  "node_modules/lru-cache/index.js"(exports2, module2) {
    "use strict";
    var Yallist = require_yallist();
    var MAX = Symbol("max");
    var LENGTH = Symbol("length");
    var LENGTH_CALCULATOR = Symbol("lengthCalculator");
    var ALLOW_STALE = Symbol("allowStale");
    var MAX_AGE = Symbol("maxAge");
    var DISPOSE = Symbol("dispose");
    var NO_DISPOSE_ON_SET = Symbol("noDisposeOnSet");
    var LRU_LIST = Symbol("lruList");
    var CACHE = Symbol("cache");
    var UPDATE_AGE_ON_GET = Symbol("updateAgeOnGet");
    var naiveLength = () => 1;
    var LRUCache = class {
      constructor(options) {
        if (typeof options === "number")
          options = { max: options };
        if (!options)
          options = {};
        if (options.max && (typeof options.max !== "number" || options.max < 0))
          throw new TypeError("max must be a non-negative number");
        const max = this[MAX] = options.max || Infinity;
        const lc = options.length || naiveLength;
        this[LENGTH_CALCULATOR] = typeof lc !== "function" ? naiveLength : lc;
        this[ALLOW_STALE] = options.stale || false;
        if (options.maxAge && typeof options.maxAge !== "number")
          throw new TypeError("maxAge must be a number");
        this[MAX_AGE] = options.maxAge || 0;
        this[DISPOSE] = options.dispose;
        this[NO_DISPOSE_ON_SET] = options.noDisposeOnSet || false;
        this[UPDATE_AGE_ON_GET] = options.updateAgeOnGet || false;
        this.reset();
      }
      // resize the cache when the max changes.
      set max(mL) {
        if (typeof mL !== "number" || mL < 0)
          throw new TypeError("max must be a non-negative number");
        this[MAX] = mL || Infinity;
        trim(this);
      }
      get max() {
        return this[MAX];
      }
      set allowStale(allowStale) {
        this[ALLOW_STALE] = !!allowStale;
      }
      get allowStale() {
        return this[ALLOW_STALE];
      }
      set maxAge(mA) {
        if (typeof mA !== "number")
          throw new TypeError("maxAge must be a non-negative number");
        this[MAX_AGE] = mA;
        trim(this);
      }
      get maxAge() {
        return this[MAX_AGE];
      }
      // resize the cache when the lengthCalculator changes.
      set lengthCalculator(lC) {
        if (typeof lC !== "function")
          lC = naiveLength;
        if (lC !== this[LENGTH_CALCULATOR]) {
          this[LENGTH_CALCULATOR] = lC;
          this[LENGTH] = 0;
          this[LRU_LIST].forEach((hit) => {
            hit.length = this[LENGTH_CALCULATOR](hit.value, hit.key);
            this[LENGTH] += hit.length;
          });
        }
        trim(this);
      }
      get lengthCalculator() {
        return this[LENGTH_CALCULATOR];
      }
      get length() {
        return this[LENGTH];
      }
      get itemCount() {
        return this[LRU_LIST].length;
      }
      rforEach(fn, thisp) {
        thisp = thisp || this;
        for (let walker = this[LRU_LIST].tail; walker !== null; ) {
          const prev = walker.prev;
          forEachStep(this, fn, walker, thisp);
          walker = prev;
        }
      }
      forEach(fn, thisp) {
        thisp = thisp || this;
        for (let walker = this[LRU_LIST].head; walker !== null; ) {
          const next = walker.next;
          forEachStep(this, fn, walker, thisp);
          walker = next;
        }
      }
      keys() {
        return this[LRU_LIST].toArray().map((k) => k.key);
      }
      values() {
        return this[LRU_LIST].toArray().map((k) => k.value);
      }
      reset() {
        if (this[DISPOSE] && this[LRU_LIST] && this[LRU_LIST].length) {
          this[LRU_LIST].forEach((hit) => this[DISPOSE](hit.key, hit.value));
        }
        this[CACHE] = /* @__PURE__ */ new Map();
        this[LRU_LIST] = new Yallist();
        this[LENGTH] = 0;
      }
      dump() {
        return this[LRU_LIST].map((hit) => isStale(this, hit) ? false : {
          k: hit.key,
          v: hit.value,
          e: hit.now + (hit.maxAge || 0)
        }).toArray().filter((h) => h);
      }
      dumpLru() {
        return this[LRU_LIST];
      }
      set(key, value, maxAge) {
        maxAge = maxAge || this[MAX_AGE];
        if (maxAge && typeof maxAge !== "number")
          throw new TypeError("maxAge must be a number");
        const now = maxAge ? Date.now() : 0;
        const len = this[LENGTH_CALCULATOR](value, key);
        if (this[CACHE].has(key)) {
          if (len > this[MAX]) {
            del(this, this[CACHE].get(key));
            return false;
          }
          const node = this[CACHE].get(key);
          const item = node.value;
          if (this[DISPOSE]) {
            if (!this[NO_DISPOSE_ON_SET])
              this[DISPOSE](key, item.value);
          }
          item.now = now;
          item.maxAge = maxAge;
          item.value = value;
          this[LENGTH] += len - item.length;
          item.length = len;
          this.get(key);
          trim(this);
          return true;
        }
        const hit = new Entry(key, value, len, now, maxAge);
        if (hit.length > this[MAX]) {
          if (this[DISPOSE])
            this[DISPOSE](key, value);
          return false;
        }
        this[LENGTH] += hit.length;
        this[LRU_LIST].unshift(hit);
        this[CACHE].set(key, this[LRU_LIST].head);
        trim(this);
        return true;
      }
      has(key) {
        if (!this[CACHE].has(key))
          return false;
        const hit = this[CACHE].get(key).value;
        return !isStale(this, hit);
      }
      get(key) {
        return get(this, key, true);
      }
      peek(key) {
        return get(this, key, false);
      }
      pop() {
        const node = this[LRU_LIST].tail;
        if (!node)
          return null;
        del(this, node);
        return node.value;
      }
      del(key) {
        del(this, this[CACHE].get(key));
      }
      load(arr) {
        this.reset();
        const now = Date.now();
        for (let l = arr.length - 1; l >= 0; l--) {
          const hit = arr[l];
          const expiresAt = hit.e || 0;
          if (expiresAt === 0)
            this.set(hit.k, hit.v);
          else {
            const maxAge = expiresAt - now;
            if (maxAge > 0) {
              this.set(hit.k, hit.v, maxAge);
            }
          }
        }
      }
      prune() {
        this[CACHE].forEach((value, key) => get(this, key, false));
      }
    };
    var get = (self2, key, doUse) => {
      const node = self2[CACHE].get(key);
      if (node) {
        const hit = node.value;
        if (isStale(self2, hit)) {
          del(self2, node);
          if (!self2[ALLOW_STALE])
            return void 0;
        } else {
          if (doUse) {
            if (self2[UPDATE_AGE_ON_GET])
              node.value.now = Date.now();
            self2[LRU_LIST].unshiftNode(node);
          }
        }
        return hit.value;
      }
    };
    var isStale = (self2, hit) => {
      if (!hit || !hit.maxAge && !self2[MAX_AGE])
        return false;
      const diff = Date.now() - hit.now;
      return hit.maxAge ? diff > hit.maxAge : self2[MAX_AGE] && diff > self2[MAX_AGE];
    };
    var trim = (self2) => {
      if (self2[LENGTH] > self2[MAX]) {
        for (let walker = self2[LRU_LIST].tail; self2[LENGTH] > self2[MAX] && walker !== null; ) {
          const prev = walker.prev;
          del(self2, walker);
          walker = prev;
        }
      }
    };
    var del = (self2, node) => {
      if (node) {
        const hit = node.value;
        if (self2[DISPOSE])
          self2[DISPOSE](hit.key, hit.value);
        self2[LENGTH] -= hit.length;
        self2[CACHE].delete(hit.key);
        self2[LRU_LIST].removeNode(node);
      }
    };
    var Entry = class {
      constructor(key, value, length, now, maxAge) {
        this.key = key;
        this.value = value;
        this.length = length;
        this.now = now;
        this.maxAge = maxAge || 0;
      }
    };
    var forEachStep = (self2, fn, node, thisp) => {
      let hit = node.value;
      if (isStale(self2, hit)) {
        del(self2, node);
        if (!self2[ALLOW_STALE])
          hit = void 0;
      }
      if (hit)
        fn.call(thisp, hit.value, hit.key, self2);
    };
    module2.exports = LRUCache;
  }
});

// node_modules/semver/classes/range.js
var require_range = __commonJS({
  "node_modules/semver/classes/range.js"(exports2, module2) {
    var Range = class _Range {
      constructor(range, options) {
        options = parseOptions(options);
        if (range instanceof _Range) {
          if (range.loose === !!options.loose && range.includePrerelease === !!options.includePrerelease) {
            return range;
          } else {
            return new _Range(range.raw, options);
          }
        }
        if (range instanceof Comparator) {
          this.raw = range.value;
          this.set = [[range]];
          this.format();
          return this;
        }
        this.options = options;
        this.loose = !!options.loose;
        this.includePrerelease = !!options.includePrerelease;
        this.raw = range.trim().split(/\s+/).join(" ");
        this.set = this.raw.split("||").map((r) => this.parseRange(r.trim())).filter((c) => c.length);
        if (!this.set.length) {
          throw new TypeError(`Invalid SemVer Range: ${this.raw}`);
        }
        if (this.set.length > 1) {
          const first = this.set[0];
          this.set = this.set.filter((c) => !isNullSet(c[0]));
          if (this.set.length === 0) {
            this.set = [first];
          } else if (this.set.length > 1) {
            for (const c of this.set) {
              if (c.length === 1 && isAny(c[0])) {
                this.set = [c];
                break;
              }
            }
          }
        }
        this.format();
      }
      format() {
        this.range = this.set.map((comps) => comps.join(" ").trim()).join("||").trim();
        return this.range;
      }
      toString() {
        return this.range;
      }
      parseRange(range) {
        const memoOpts = (this.options.includePrerelease && FLAG_INCLUDE_PRERELEASE) | (this.options.loose && FLAG_LOOSE);
        const memoKey = memoOpts + ":" + range;
        const cached = cache.get(memoKey);
        if (cached) {
          return cached;
        }
        const loose = this.options.loose;
        const hr = loose ? re[t.HYPHENRANGELOOSE] : re[t.HYPHENRANGE];
        range = range.replace(hr, hyphenReplace(this.options.includePrerelease));
        debug2("hyphen replace", range);
        range = range.replace(re[t.COMPARATORTRIM], comparatorTrimReplace);
        debug2("comparator trim", range);
        range = range.replace(re[t.TILDETRIM], tildeTrimReplace);
        debug2("tilde trim", range);
        range = range.replace(re[t.CARETTRIM], caretTrimReplace);
        debug2("caret trim", range);
        let rangeList = range.split(" ").map((comp) => parseComparator(comp, this.options)).join(" ").split(/\s+/).map((comp) => replaceGTE0(comp, this.options));
        if (loose) {
          rangeList = rangeList.filter((comp) => {
            debug2("loose invalid filter", comp, this.options);
            return !!comp.match(re[t.COMPARATORLOOSE]);
          });
        }
        debug2("range list", rangeList);
        const rangeMap = /* @__PURE__ */ new Map();
        const comparators = rangeList.map((comp) => new Comparator(comp, this.options));
        for (const comp of comparators) {
          if (isNullSet(comp)) {
            return [comp];
          }
          rangeMap.set(comp.value, comp);
        }
        if (rangeMap.size > 1 && rangeMap.has("")) {
          rangeMap.delete("");
        }
        const result = [...rangeMap.values()];
        cache.set(memoKey, result);
        return result;
      }
      intersects(range, options) {
        if (!(range instanceof _Range)) {
          throw new TypeError("a Range is required");
        }
        return this.set.some((thisComparators) => {
          return isSatisfiable(thisComparators, options) && range.set.some((rangeComparators) => {
            return isSatisfiable(rangeComparators, options) && thisComparators.every((thisComparator) => {
              return rangeComparators.every((rangeComparator) => {
                return thisComparator.intersects(rangeComparator, options);
              });
            });
          });
        });
      }
      // if ANY of the sets match ALL of its comparators, then pass
      test(version2) {
        if (!version2) {
          return false;
        }
        if (typeof version2 === "string") {
          try {
            version2 = new SemVer(version2, this.options);
          } catch (er) {
            return false;
          }
        }
        for (let i = 0; i < this.set.length; i++) {
          if (testSet(this.set[i], version2, this.options)) {
            return true;
          }
        }
        return false;
      }
    };
    module2.exports = Range;
    var LRU = require_lru_cache();
    var cache = new LRU({ max: 1e3 });
    var parseOptions = require_parse_options();
    var Comparator = require_comparator();
    var debug2 = require_debug();
    var SemVer = require_semver();
    var {
      safeRe: re,
      t,
      comparatorTrimReplace,
      tildeTrimReplace,
      caretTrimReplace
    } = require_re();
    var { FLAG_INCLUDE_PRERELEASE, FLAG_LOOSE } = require_constants();
    var isNullSet = (c) => c.value === "<0.0.0-0";
    var isAny = (c) => c.value === "";
    var isSatisfiable = (comparators, options) => {
      let result = true;
      const remainingComparators = comparators.slice();
      let testComparator = remainingComparators.pop();
      while (result && remainingComparators.length) {
        result = remainingComparators.every((otherComparator) => {
          return testComparator.intersects(otherComparator, options);
        });
        testComparator = remainingComparators.pop();
      }
      return result;
    };
    var parseComparator = (comp, options) => {
      debug2("comp", comp, options);
      comp = replaceCarets(comp, options);
      debug2("caret", comp);
      comp = replaceTildes(comp, options);
      debug2("tildes", comp);
      comp = replaceXRanges(comp, options);
      debug2("xrange", comp);
      comp = replaceStars(comp, options);
      debug2("stars", comp);
      return comp;
    };
    var isX = (id) => !id || id.toLowerCase() === "x" || id === "*";
    var replaceTildes = (comp, options) => {
      return comp.trim().split(/\s+/).map((c) => replaceTilde(c, options)).join(" ");
    };
    var replaceTilde = (comp, options) => {
      const r = options.loose ? re[t.TILDELOOSE] : re[t.TILDE];
      return comp.replace(r, (_, M, m, p, pr) => {
        debug2("tilde", comp, _, M, m, p, pr);
        let ret;
        if (isX(M)) {
          ret = "";
        } else if (isX(m)) {
          ret = `>=${M}.0.0 <${+M + 1}.0.0-0`;
        } else if (isX(p)) {
          ret = `>=${M}.${m}.0 <${M}.${+m + 1}.0-0`;
        } else if (pr) {
          debug2("replaceTilde pr", pr);
          ret = `>=${M}.${m}.${p}-${pr} <${M}.${+m + 1}.0-0`;
        } else {
          ret = `>=${M}.${m}.${p} <${M}.${+m + 1}.0-0`;
        }
        debug2("tilde return", ret);
        return ret;
      });
    };
    var replaceCarets = (comp, options) => {
      return comp.trim().split(/\s+/).map((c) => replaceCaret(c, options)).join(" ");
    };
    var replaceCaret = (comp, options) => {
      debug2("caret", comp, options);
      const r = options.loose ? re[t.CARETLOOSE] : re[t.CARET];
      const z = options.includePrerelease ? "-0" : "";
      return comp.replace(r, (_, M, m, p, pr) => {
        debug2("caret", comp, _, M, m, p, pr);
        let ret;
        if (isX(M)) {
          ret = "";
        } else if (isX(m)) {
          ret = `>=${M}.0.0${z} <${+M + 1}.0.0-0`;
        } else if (isX(p)) {
          if (M === "0") {
            ret = `>=${M}.${m}.0${z} <${M}.${+m + 1}.0-0`;
          } else {
            ret = `>=${M}.${m}.0${z} <${+M + 1}.0.0-0`;
          }
        } else if (pr) {
          debug2("replaceCaret pr", pr);
          if (M === "0") {
            if (m === "0") {
              ret = `>=${M}.${m}.${p}-${pr} <${M}.${m}.${+p + 1}-0`;
            } else {
              ret = `>=${M}.${m}.${p}-${pr} <${M}.${+m + 1}.0-0`;
            }
          } else {
            ret = `>=${M}.${m}.${p}-${pr} <${+M + 1}.0.0-0`;
          }
        } else {
          debug2("no pr");
          if (M === "0") {
            if (m === "0") {
              ret = `>=${M}.${m}.${p}${z} <${M}.${m}.${+p + 1}-0`;
            } else {
              ret = `>=${M}.${m}.${p}${z} <${M}.${+m + 1}.0-0`;
            }
          } else {
            ret = `>=${M}.${m}.${p} <${+M + 1}.0.0-0`;
          }
        }
        debug2("caret return", ret);
        return ret;
      });
    };
    var replaceXRanges = (comp, options) => {
      debug2("replaceXRanges", comp, options);
      return comp.split(/\s+/).map((c) => replaceXRange(c, options)).join(" ");
    };
    var replaceXRange = (comp, options) => {
      comp = comp.trim();
      const r = options.loose ? re[t.XRANGELOOSE] : re[t.XRANGE];
      return comp.replace(r, (ret, gtlt, M, m, p, pr) => {
        debug2("xRange", comp, ret, gtlt, M, m, p, pr);
        const xM = isX(M);
        const xm = xM || isX(m);
        const xp = xm || isX(p);
        const anyX = xp;
        if (gtlt === "=" && anyX) {
          gtlt = "";
        }
        pr = options.includePrerelease ? "-0" : "";
        if (xM) {
          if (gtlt === ">" || gtlt === "<") {
            ret = "<0.0.0-0";
          } else {
            ret = "*";
          }
        } else if (gtlt && anyX) {
          if (xm) {
            m = 0;
          }
          p = 0;
          if (gtlt === ">") {
            gtlt = ">=";
            if (xm) {
              M = +M + 1;
              m = 0;
              p = 0;
            } else {
              m = +m + 1;
              p = 0;
            }
          } else if (gtlt === "<=") {
            gtlt = "<";
            if (xm) {
              M = +M + 1;
            } else {
              m = +m + 1;
            }
          }
          if (gtlt === "<") {
            pr = "-0";
          }
          ret = `${gtlt + M}.${m}.${p}${pr}`;
        } else if (xm) {
          ret = `>=${M}.0.0${pr} <${+M + 1}.0.0-0`;
        } else if (xp) {
          ret = `>=${M}.${m}.0${pr} <${M}.${+m + 1}.0-0`;
        }
        debug2("xRange return", ret);
        return ret;
      });
    };
    var replaceStars = (comp, options) => {
      debug2("replaceStars", comp, options);
      return comp.trim().replace(re[t.STAR], "");
    };
    var replaceGTE0 = (comp, options) => {
      debug2("replaceGTE0", comp, options);
      return comp.trim().replace(re[options.includePrerelease ? t.GTE0PRE : t.GTE0], "");
    };
    var hyphenReplace = (incPr) => ($0, from, fM, fm, fp, fpr, fb, to, tM, tm, tp, tpr, tb) => {
      if (isX(fM)) {
        from = "";
      } else if (isX(fm)) {
        from = `>=${fM}.0.0${incPr ? "-0" : ""}`;
      } else if (isX(fp)) {
        from = `>=${fM}.${fm}.0${incPr ? "-0" : ""}`;
      } else if (fpr) {
        from = `>=${from}`;
      } else {
        from = `>=${from}${incPr ? "-0" : ""}`;
      }
      if (isX(tM)) {
        to = "";
      } else if (isX(tm)) {
        to = `<${+tM + 1}.0.0-0`;
      } else if (isX(tp)) {
        to = `<${tM}.${+tm + 1}.0-0`;
      } else if (tpr) {
        to = `<=${tM}.${tm}.${tp}-${tpr}`;
      } else if (incPr) {
        to = `<${tM}.${tm}.${+tp + 1}-0`;
      } else {
        to = `<=${to}`;
      }
      return `${from} ${to}`.trim();
    };
    var testSet = (set, version2, options) => {
      for (let i = 0; i < set.length; i++) {
        if (!set[i].test(version2)) {
          return false;
        }
      }
      if (version2.prerelease.length && !options.includePrerelease) {
        for (let i = 0; i < set.length; i++) {
          debug2(set[i].semver);
          if (set[i].semver === Comparator.ANY) {
            continue;
          }
          if (set[i].semver.prerelease.length > 0) {
            const allowed = set[i].semver;
            if (allowed.major === version2.major && allowed.minor === version2.minor && allowed.patch === version2.patch) {
              return true;
            }
          }
        }
        return false;
      }
      return true;
    };
  }
});

// node_modules/semver/classes/comparator.js
var require_comparator = __commonJS({
  "node_modules/semver/classes/comparator.js"(exports2, module2) {
    var ANY = Symbol("SemVer ANY");
    var Comparator = class _Comparator {
      static get ANY() {
        return ANY;
      }
      constructor(comp, options) {
        options = parseOptions(options);
        if (comp instanceof _Comparator) {
          if (comp.loose === !!options.loose) {
            return comp;
          } else {
            comp = comp.value;
          }
        }
        comp = comp.trim().split(/\s+/).join(" ");
        debug2("comparator", comp, options);
        this.options = options;
        this.loose = !!options.loose;
        this.parse(comp);
        if (this.semver === ANY) {
          this.value = "";
        } else {
          this.value = this.operator + this.semver.version;
        }
        debug2("comp", this);
      }
      parse(comp) {
        const r = this.options.loose ? re[t.COMPARATORLOOSE] : re[t.COMPARATOR];
        const m = comp.match(r);
        if (!m) {
          throw new TypeError(`Invalid comparator: ${comp}`);
        }
        this.operator = m[1] !== void 0 ? m[1] : "";
        if (this.operator === "=") {
          this.operator = "";
        }
        if (!m[2]) {
          this.semver = ANY;
        } else {
          this.semver = new SemVer(m[2], this.options.loose);
        }
      }
      toString() {
        return this.value;
      }
      test(version2) {
        debug2("Comparator.test", version2, this.options.loose);
        if (this.semver === ANY || version2 === ANY) {
          return true;
        }
        if (typeof version2 === "string") {
          try {
            version2 = new SemVer(version2, this.options);
          } catch (er) {
            return false;
          }
        }
        return cmp(version2, this.operator, this.semver, this.options);
      }
      intersects(comp, options) {
        if (!(comp instanceof _Comparator)) {
          throw new TypeError("a Comparator is required");
        }
        if (this.operator === "") {
          if (this.value === "") {
            return true;
          }
          return new Range(comp.value, options).test(this.value);
        } else if (comp.operator === "") {
          if (comp.value === "") {
            return true;
          }
          return new Range(this.value, options).test(comp.semver);
        }
        options = parseOptions(options);
        if (options.includePrerelease && (this.value === "<0.0.0-0" || comp.value === "<0.0.0-0")) {
          return false;
        }
        if (!options.includePrerelease && (this.value.startsWith("<0.0.0") || comp.value.startsWith("<0.0.0"))) {
          return false;
        }
        if (this.operator.startsWith(">") && comp.operator.startsWith(">")) {
          return true;
        }
        if (this.operator.startsWith("<") && comp.operator.startsWith("<")) {
          return true;
        }
        if (this.semver.version === comp.semver.version && this.operator.includes("=") && comp.operator.includes("=")) {
          return true;
        }
        if (cmp(this.semver, "<", comp.semver, options) && this.operator.startsWith(">") && comp.operator.startsWith("<")) {
          return true;
        }
        if (cmp(this.semver, ">", comp.semver, options) && this.operator.startsWith("<") && comp.operator.startsWith(">")) {
          return true;
        }
        return false;
      }
    };
    module2.exports = Comparator;
    var parseOptions = require_parse_options();
    var { safeRe: re, t } = require_re();
    var cmp = require_cmp();
    var debug2 = require_debug();
    var SemVer = require_semver();
    var Range = require_range();
  }
});

// node_modules/semver/functions/satisfies.js
var require_satisfies = __commonJS({
  "node_modules/semver/functions/satisfies.js"(exports2, module2) {
    var Range = require_range();
    var satisfies = (version2, range, options) => {
      try {
        range = new Range(range, options);
      } catch (er) {
        return false;
      }
      return range.test(version2);
    };
    module2.exports = satisfies;
  }
});

// node_modules/semver/ranges/to-comparators.js
var require_to_comparators = __commonJS({
  "node_modules/semver/ranges/to-comparators.js"(exports2, module2) {
    var Range = require_range();
    var toComparators = (range, options) => new Range(range, options).set.map((comp) => comp.map((c) => c.value).join(" ").trim().split(" "));
    module2.exports = toComparators;
  }
});

// node_modules/semver/ranges/max-satisfying.js
var require_max_satisfying = __commonJS({
  "node_modules/semver/ranges/max-satisfying.js"(exports2, module2) {
    var SemVer = require_semver();
    var Range = require_range();
    var maxSatisfying = (versions, range, options) => {
      let max = null;
      let maxSV = null;
      let rangeObj = null;
      try {
        rangeObj = new Range(range, options);
      } catch (er) {
        return null;
      }
      versions.forEach((v) => {
        if (rangeObj.test(v)) {
          if (!max || maxSV.compare(v) === -1) {
            max = v;
            maxSV = new SemVer(max, options);
          }
        }
      });
      return max;
    };
    module2.exports = maxSatisfying;
  }
});

// node_modules/semver/ranges/min-satisfying.js
var require_min_satisfying = __commonJS({
  "node_modules/semver/ranges/min-satisfying.js"(exports2, module2) {
    var SemVer = require_semver();
    var Range = require_range();
    var minSatisfying = (versions, range, options) => {
      let min = null;
      let minSV = null;
      let rangeObj = null;
      try {
        rangeObj = new Range(range, options);
      } catch (er) {
        return null;
      }
      versions.forEach((v) => {
        if (rangeObj.test(v)) {
          if (!min || minSV.compare(v) === 1) {
            min = v;
            minSV = new SemVer(min, options);
          }
        }
      });
      return min;
    };
    module2.exports = minSatisfying;
  }
});

// node_modules/semver/ranges/min-version.js
var require_min_version = __commonJS({
  "node_modules/semver/ranges/min-version.js"(exports2, module2) {
    var SemVer = require_semver();
    var Range = require_range();
    var gt = require_gt();
    var minVersion = (range, loose) => {
      range = new Range(range, loose);
      let minver = new SemVer("0.0.0");
      if (range.test(minver)) {
        return minver;
      }
      minver = new SemVer("0.0.0-0");
      if (range.test(minver)) {
        return minver;
      }
      minver = null;
      for (let i = 0; i < range.set.length; ++i) {
        const comparators = range.set[i];
        let setMin = null;
        comparators.forEach((comparator) => {
          const compver = new SemVer(comparator.semver.version);
          switch (comparator.operator) {
            case ">":
              if (compver.prerelease.length === 0) {
                compver.patch++;
              } else {
                compver.prerelease.push(0);
              }
              compver.raw = compver.format();
            case "":
            case ">=":
              if (!setMin || gt(compver, setMin)) {
                setMin = compver;
              }
              break;
            case "<":
            case "<=":
              break;
            default:
              throw new Error(`Unexpected operation: ${comparator.operator}`);
          }
        });
        if (setMin && (!minver || gt(minver, setMin))) {
          minver = setMin;
        }
      }
      if (minver && range.test(minver)) {
        return minver;
      }
      return null;
    };
    module2.exports = minVersion;
  }
});

// node_modules/semver/ranges/valid.js
var require_valid2 = __commonJS({
  "node_modules/semver/ranges/valid.js"(exports2, module2) {
    var Range = require_range();
    var validRange = (range, options) => {
      try {
        return new Range(range, options).range || "*";
      } catch (er) {
        return null;
      }
    };
    module2.exports = validRange;
  }
});

// node_modules/semver/ranges/outside.js
var require_outside = __commonJS({
  "node_modules/semver/ranges/outside.js"(exports2, module2) {
    var SemVer = require_semver();
    var Comparator = require_comparator();
    var { ANY } = Comparator;
    var Range = require_range();
    var satisfies = require_satisfies();
    var gt = require_gt();
    var lt = require_lt();
    var lte = require_lte();
    var gte = require_gte();
    var outside = (version2, range, hilo, options) => {
      version2 = new SemVer(version2, options);
      range = new Range(range, options);
      let gtfn, ltefn, ltfn, comp, ecomp;
      switch (hilo) {
        case ">":
          gtfn = gt;
          ltefn = lte;
          ltfn = lt;
          comp = ">";
          ecomp = ">=";
          break;
        case "<":
          gtfn = lt;
          ltefn = gte;
          ltfn = gt;
          comp = "<";
          ecomp = "<=";
          break;
        default:
          throw new TypeError('Must provide a hilo val of "<" or ">"');
      }
      if (satisfies(version2, range, options)) {
        return false;
      }
      for (let i = 0; i < range.set.length; ++i) {
        const comparators = range.set[i];
        let high = null;
        let low = null;
        comparators.forEach((comparator) => {
          if (comparator.semver === ANY) {
            comparator = new Comparator(">=0.0.0");
          }
          high = high || comparator;
          low = low || comparator;
          if (gtfn(comparator.semver, high.semver, options)) {
            high = comparator;
          } else if (ltfn(comparator.semver, low.semver, options)) {
            low = comparator;
          }
        });
        if (high.operator === comp || high.operator === ecomp) {
          return false;
        }
        if ((!low.operator || low.operator === comp) && ltefn(version2, low.semver)) {
          return false;
        } else if (low.operator === ecomp && ltfn(version2, low.semver)) {
          return false;
        }
      }
      return true;
    };
    module2.exports = outside;
  }
});

// node_modules/semver/ranges/gtr.js
var require_gtr = __commonJS({
  "node_modules/semver/ranges/gtr.js"(exports2, module2) {
    var outside = require_outside();
    var gtr = (version2, range, options) => outside(version2, range, ">", options);
    module2.exports = gtr;
  }
});

// node_modules/semver/ranges/ltr.js
var require_ltr = __commonJS({
  "node_modules/semver/ranges/ltr.js"(exports2, module2) {
    var outside = require_outside();
    var ltr = (version2, range, options) => outside(version2, range, "<", options);
    module2.exports = ltr;
  }
});

// node_modules/semver/ranges/intersects.js
var require_intersects = __commonJS({
  "node_modules/semver/ranges/intersects.js"(exports2, module2) {
    var Range = require_range();
    var intersects = (r1, r2, options) => {
      r1 = new Range(r1, options);
      r2 = new Range(r2, options);
      return r1.intersects(r2, options);
    };
    module2.exports = intersects;
  }
});

// node_modules/semver/ranges/simplify.js
var require_simplify = __commonJS({
  "node_modules/semver/ranges/simplify.js"(exports2, module2) {
    var satisfies = require_satisfies();
    var compare = require_compare();
    module2.exports = (versions, range, options) => {
      const set = [];
      let first = null;
      let prev = null;
      const v = versions.sort((a, b) => compare(a, b, options));
      for (const version2 of v) {
        const included = satisfies(version2, range, options);
        if (included) {
          prev = version2;
          if (!first) {
            first = version2;
          }
        } else {
          if (prev) {
            set.push([first, prev]);
          }
          prev = null;
          first = null;
        }
      }
      if (first) {
        set.push([first, null]);
      }
      const ranges = [];
      for (const [min, max] of set) {
        if (min === max) {
          ranges.push(min);
        } else if (!max && min === v[0]) {
          ranges.push("*");
        } else if (!max) {
          ranges.push(`>=${min}`);
        } else if (min === v[0]) {
          ranges.push(`<=${max}`);
        } else {
          ranges.push(`${min} - ${max}`);
        }
      }
      const simplified = ranges.join(" || ");
      const original = typeof range.raw === "string" ? range.raw : String(range);
      return simplified.length < original.length ? simplified : range;
    };
  }
});

// node_modules/semver/ranges/subset.js
var require_subset = __commonJS({
  "node_modules/semver/ranges/subset.js"(exports2, module2) {
    var Range = require_range();
    var Comparator = require_comparator();
    var { ANY } = Comparator;
    var satisfies = require_satisfies();
    var compare = require_compare();
    var subset = (sub, dom, options = {}) => {
      if (sub === dom) {
        return true;
      }
      sub = new Range(sub, options);
      dom = new Range(dom, options);
      let sawNonNull = false;
      OUTER:
        for (const simpleSub of sub.set) {
          for (const simpleDom of dom.set) {
            const isSub = simpleSubset(simpleSub, simpleDom, options);
            sawNonNull = sawNonNull || isSub !== null;
            if (isSub) {
              continue OUTER;
            }
          }
          if (sawNonNull) {
            return false;
          }
        }
      return true;
    };
    var minimumVersionWithPreRelease = [new Comparator(">=0.0.0-0")];
    var minimumVersion = [new Comparator(">=0.0.0")];
    var simpleSubset = (sub, dom, options) => {
      if (sub === dom) {
        return true;
      }
      if (sub.length === 1 && sub[0].semver === ANY) {
        if (dom.length === 1 && dom[0].semver === ANY) {
          return true;
        } else if (options.includePrerelease) {
          sub = minimumVersionWithPreRelease;
        } else {
          sub = minimumVersion;
        }
      }
      if (dom.length === 1 && dom[0].semver === ANY) {
        if (options.includePrerelease) {
          return true;
        } else {
          dom = minimumVersion;
        }
      }
      const eqSet = /* @__PURE__ */ new Set();
      let gt, lt;
      for (const c of sub) {
        if (c.operator === ">" || c.operator === ">=") {
          gt = higherGT(gt, c, options);
        } else if (c.operator === "<" || c.operator === "<=") {
          lt = lowerLT(lt, c, options);
        } else {
          eqSet.add(c.semver);
        }
      }
      if (eqSet.size > 1) {
        return null;
      }
      let gtltComp;
      if (gt && lt) {
        gtltComp = compare(gt.semver, lt.semver, options);
        if (gtltComp > 0) {
          return null;
        } else if (gtltComp === 0 && (gt.operator !== ">=" || lt.operator !== "<=")) {
          return null;
        }
      }
      for (const eq of eqSet) {
        if (gt && !satisfies(eq, String(gt), options)) {
          return null;
        }
        if (lt && !satisfies(eq, String(lt), options)) {
          return null;
        }
        for (const c of dom) {
          if (!satisfies(eq, String(c), options)) {
            return false;
          }
        }
        return true;
      }
      let higher, lower;
      let hasDomLT, hasDomGT;
      let needDomLTPre = lt && !options.includePrerelease && lt.semver.prerelease.length ? lt.semver : false;
      let needDomGTPre = gt && !options.includePrerelease && gt.semver.prerelease.length ? gt.semver : false;
      if (needDomLTPre && needDomLTPre.prerelease.length === 1 && lt.operator === "<" && needDomLTPre.prerelease[0] === 0) {
        needDomLTPre = false;
      }
      for (const c of dom) {
        hasDomGT = hasDomGT || c.operator === ">" || c.operator === ">=";
        hasDomLT = hasDomLT || c.operator === "<" || c.operator === "<=";
        if (gt) {
          if (needDomGTPre) {
            if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomGTPre.major && c.semver.minor === needDomGTPre.minor && c.semver.patch === needDomGTPre.patch) {
              needDomGTPre = false;
            }
          }
          if (c.operator === ">" || c.operator === ">=") {
            higher = higherGT(gt, c, options);
            if (higher === c && higher !== gt) {
              return false;
            }
          } else if (gt.operator === ">=" && !satisfies(gt.semver, String(c), options)) {
            return false;
          }
        }
        if (lt) {
          if (needDomLTPre) {
            if (c.semver.prerelease && c.semver.prerelease.length && c.semver.major === needDomLTPre.major && c.semver.minor === needDomLTPre.minor && c.semver.patch === needDomLTPre.patch) {
              needDomLTPre = false;
            }
          }
          if (c.operator === "<" || c.operator === "<=") {
            lower = lowerLT(lt, c, options);
            if (lower === c && lower !== lt) {
              return false;
            }
          } else if (lt.operator === "<=" && !satisfies(lt.semver, String(c), options)) {
            return false;
          }
        }
        if (!c.operator && (lt || gt) && gtltComp !== 0) {
          return false;
        }
      }
      if (gt && hasDomLT && !lt && gtltComp !== 0) {
        return false;
      }
      if (lt && hasDomGT && !gt && gtltComp !== 0) {
        return false;
      }
      if (needDomGTPre || needDomLTPre) {
        return false;
      }
      return true;
    };
    var higherGT = (a, b, options) => {
      if (!a) {
        return b;
      }
      const comp = compare(a.semver, b.semver, options);
      return comp > 0 ? a : comp < 0 ? b : b.operator === ">" && a.operator === ">=" ? b : a;
    };
    var lowerLT = (a, b, options) => {
      if (!a) {
        return b;
      }
      const comp = compare(a.semver, b.semver, options);
      return comp < 0 ? a : comp > 0 ? b : b.operator === "<" && a.operator === "<=" ? b : a;
    };
    module2.exports = subset;
  }
});

// node_modules/semver/index.js
var require_semver2 = __commonJS({
  "node_modules/semver/index.js"(exports2, module2) {
    var internalRe = require_re();
    var constants = require_constants();
    var SemVer = require_semver();
    var identifiers = require_identifiers();
    var parse2 = require_parse();
    var valid = require_valid();
    var clean = require_clean();
    var inc = require_inc();
    var diff = require_diff();
    var major = require_major();
    var minor = require_minor();
    var patch = require_patch();
    var prerelease = require_prerelease();
    var compare = require_compare();
    var rcompare = require_rcompare();
    var compareLoose = require_compare_loose();
    var compareBuild = require_compare_build();
    var sort = require_sort();
    var rsort = require_rsort();
    var gt = require_gt();
    var lt = require_lt();
    var eq = require_eq();
    var neq = require_neq();
    var gte = require_gte();
    var lte = require_lte();
    var cmp = require_cmp();
    var coerce = require_coerce();
    var Comparator = require_comparator();
    var Range = require_range();
    var satisfies = require_satisfies();
    var toComparators = require_to_comparators();
    var maxSatisfying = require_max_satisfying();
    var minSatisfying = require_min_satisfying();
    var minVersion = require_min_version();
    var validRange = require_valid2();
    var outside = require_outside();
    var gtr = require_gtr();
    var ltr = require_ltr();
    var intersects = require_intersects();
    var simplifyRange = require_simplify();
    var subset = require_subset();
    module2.exports = {
      parse: parse2,
      valid,
      clean,
      inc,
      diff,
      major,
      minor,
      patch,
      prerelease,
      compare,
      rcompare,
      compareLoose,
      compareBuild,
      sort,
      rsort,
      gt,
      lt,
      eq,
      neq,
      gte,
      lte,
      cmp,
      coerce,
      Comparator,
      Range,
      satisfies,
      toComparators,
      maxSatisfying,
      minSatisfying,
      minVersion,
      validRange,
      outside,
      gtr,
      ltr,
      intersects,
      simplifyRange,
      subset,
      SemVer,
      re: internalRe.re,
      src: internalRe.src,
      tokens: internalRe.t,
      SEMVER_SPEC_VERSION: constants.SEMVER_SPEC_VERSION,
      RELEASE_TYPES: constants.RELEASE_TYPES,
      compareIdentifiers: identifiers.compareIdentifiers,
      rcompareIdentifiers: identifiers.rcompareIdentifiers
    };
  }
});

// node_modules/jsonwebtoken/lib/asymmetricKeyDetailsSupported.js
var require_asymmetricKeyDetailsSupported = __commonJS({
  "node_modules/jsonwebtoken/lib/asymmetricKeyDetailsSupported.js"(exports2, module2) {
    var semver = require_semver2();
    module2.exports = semver.satisfies(process.version, ">=15.7.0");
  }
});

// node_modules/jsonwebtoken/lib/rsaPssKeyDetailsSupported.js
var require_rsaPssKeyDetailsSupported = __commonJS({
  "node_modules/jsonwebtoken/lib/rsaPssKeyDetailsSupported.js"(exports2, module2) {
    var semver = require_semver2();
    module2.exports = semver.satisfies(process.version, ">=16.9.0");
  }
});

// node_modules/jsonwebtoken/lib/validateAsymmetricKey.js
var require_validateAsymmetricKey = __commonJS({
  "node_modules/jsonwebtoken/lib/validateAsymmetricKey.js"(exports2, module2) {
    var ASYMMETRIC_KEY_DETAILS_SUPPORTED = require_asymmetricKeyDetailsSupported();
    var RSA_PSS_KEY_DETAILS_SUPPORTED = require_rsaPssKeyDetailsSupported();
    var allowedAlgorithmsForKeys = {
      "ec": ["ES256", "ES384", "ES512"],
      "rsa": ["RS256", "PS256", "RS384", "PS384", "RS512", "PS512"],
      "rsa-pss": ["PS256", "PS384", "PS512"]
    };
    var allowedCurves = {
      ES256: "prime256v1",
      ES384: "secp384r1",
      ES512: "secp521r1"
    };
    module2.exports = function(algorithm, key) {
      if (!algorithm || !key)
        return;
      const keyType = key.asymmetricKeyType;
      if (!keyType)
        return;
      const allowedAlgorithms = allowedAlgorithmsForKeys[keyType];
      if (!allowedAlgorithms) {
        throw new Error(`Unknown key type "${keyType}".`);
      }
      if (!allowedAlgorithms.includes(algorithm)) {
        throw new Error(`"alg" parameter for "${keyType}" key type must be one of: ${allowedAlgorithms.join(", ")}.`);
      }
      if (ASYMMETRIC_KEY_DETAILS_SUPPORTED) {
        switch (keyType) {
          case "ec":
            const keyCurve = key.asymmetricKeyDetails.namedCurve;
            const allowedCurve = allowedCurves[algorithm];
            if (keyCurve !== allowedCurve) {
              throw new Error(`"alg" parameter "${algorithm}" requires curve "${allowedCurve}".`);
            }
            break;
          case "rsa-pss":
            if (RSA_PSS_KEY_DETAILS_SUPPORTED) {
              const length = parseInt(algorithm.slice(-3), 10);
              const { hashAlgorithm, mgf1HashAlgorithm, saltLength } = key.asymmetricKeyDetails;
              if (hashAlgorithm !== `sha${length}` || mgf1HashAlgorithm !== hashAlgorithm) {
                throw new Error(`Invalid key for this operation, its RSA-PSS parameters do not meet the requirements of "alg" ${algorithm}.`);
              }
              if (saltLength !== void 0 && saltLength > length >> 3) {
                throw new Error(`Invalid key for this operation, its RSA-PSS parameter saltLength does not meet the requirements of "alg" ${algorithm}.`);
              }
            }
            break;
        }
      }
    };
  }
});

// node_modules/jsonwebtoken/lib/psSupported.js
var require_psSupported = __commonJS({
  "node_modules/jsonwebtoken/lib/psSupported.js"(exports2, module2) {
    var semver = require_semver2();
    module2.exports = semver.satisfies(process.version, "^6.12.0 || >=8.0.0");
  }
});

// node_modules/jsonwebtoken/verify.js
var require_verify = __commonJS({
  "node_modules/jsonwebtoken/verify.js"(exports2, module2) {
    var JsonWebTokenError = require_JsonWebTokenError();
    var NotBeforeError = require_NotBeforeError();
    var TokenExpiredError = require_TokenExpiredError();
    var decode = require_decode();
    var timespan = require_timespan();
    var validateAsymmetricKey = require_validateAsymmetricKey();
    var PS_SUPPORTED = require_psSupported();
    var jws = require_jws();
    var { KeyObject, createSecretKey, createPublicKey } = require("crypto");
    var PUB_KEY_ALGS = ["RS256", "RS384", "RS512"];
    var EC_KEY_ALGS = ["ES256", "ES384", "ES512"];
    var RSA_KEY_ALGS = ["RS256", "RS384", "RS512"];
    var HS_ALGS = ["HS256", "HS384", "HS512"];
    if (PS_SUPPORTED) {
      PUB_KEY_ALGS.splice(PUB_KEY_ALGS.length, 0, "PS256", "PS384", "PS512");
      RSA_KEY_ALGS.splice(RSA_KEY_ALGS.length, 0, "PS256", "PS384", "PS512");
    }
    module2.exports = function(jwtString, secretOrPublicKey, options, callback) {
      if (typeof options === "function" && !callback) {
        callback = options;
        options = {};
      }
      if (!options) {
        options = {};
      }
      options = Object.assign({}, options);
      let done;
      if (callback) {
        done = callback;
      } else {
        done = function(err, data) {
          if (err)
            throw err;
          return data;
        };
      }
      if (options.clockTimestamp && typeof options.clockTimestamp !== "number") {
        return done(new JsonWebTokenError("clockTimestamp must be a number"));
      }
      if (options.nonce !== void 0 && (typeof options.nonce !== "string" || options.nonce.trim() === "")) {
        return done(new JsonWebTokenError("nonce must be a non-empty string"));
      }
      if (options.allowInvalidAsymmetricKeyTypes !== void 0 && typeof options.allowInvalidAsymmetricKeyTypes !== "boolean") {
        return done(new JsonWebTokenError("allowInvalidAsymmetricKeyTypes must be a boolean"));
      }
      const clockTimestamp = options.clockTimestamp || Math.floor(Date.now() / 1e3);
      if (!jwtString) {
        return done(new JsonWebTokenError("jwt must be provided"));
      }
      if (typeof jwtString !== "string") {
        return done(new JsonWebTokenError("jwt must be a string"));
      }
      const parts = jwtString.split(".");
      if (parts.length !== 3) {
        return done(new JsonWebTokenError("jwt malformed"));
      }
      let decodedToken;
      try {
        decodedToken = decode(jwtString, { complete: true });
      } catch (err) {
        return done(err);
      }
      if (!decodedToken) {
        return done(new JsonWebTokenError("invalid token"));
      }
      const header = decodedToken.header;
      let getSecret;
      if (typeof secretOrPublicKey === "function") {
        if (!callback) {
          return done(new JsonWebTokenError("verify must be called asynchronous if secret or public key is provided as a callback"));
        }
        getSecret = secretOrPublicKey;
      } else {
        getSecret = function(header2, secretCallback) {
          return secretCallback(null, secretOrPublicKey);
        };
      }
      return getSecret(header, function(err, secretOrPublicKey2) {
        if (err) {
          return done(new JsonWebTokenError("error in secret or public key callback: " + err.message));
        }
        const hasSignature = parts[2].trim() !== "";
        if (!hasSignature && secretOrPublicKey2) {
          return done(new JsonWebTokenError("jwt signature is required"));
        }
        if (hasSignature && !secretOrPublicKey2) {
          return done(new JsonWebTokenError("secret or public key must be provided"));
        }
        if (!hasSignature && !options.algorithms) {
          return done(new JsonWebTokenError('please specify "none" in "algorithms" to verify unsigned tokens'));
        }
        if (secretOrPublicKey2 != null && !(secretOrPublicKey2 instanceof KeyObject)) {
          try {
            secretOrPublicKey2 = createPublicKey(secretOrPublicKey2);
          } catch (_) {
            try {
              secretOrPublicKey2 = createSecretKey(typeof secretOrPublicKey2 === "string" ? Buffer.from(secretOrPublicKey2) : secretOrPublicKey2);
            } catch (_2) {
              return done(new JsonWebTokenError("secretOrPublicKey is not valid key material"));
            }
          }
        }
        if (!options.algorithms) {
          if (secretOrPublicKey2.type === "secret") {
            options.algorithms = HS_ALGS;
          } else if (["rsa", "rsa-pss"].includes(secretOrPublicKey2.asymmetricKeyType)) {
            options.algorithms = RSA_KEY_ALGS;
          } else if (secretOrPublicKey2.asymmetricKeyType === "ec") {
            options.algorithms = EC_KEY_ALGS;
          } else {
            options.algorithms = PUB_KEY_ALGS;
          }
        }
        if (options.algorithms.indexOf(decodedToken.header.alg) === -1) {
          return done(new JsonWebTokenError("invalid algorithm"));
        }
        if (header.alg.startsWith("HS") && secretOrPublicKey2.type !== "secret") {
          return done(new JsonWebTokenError(`secretOrPublicKey must be a symmetric key when using ${header.alg}`));
        } else if (/^(?:RS|PS|ES)/.test(header.alg) && secretOrPublicKey2.type !== "public") {
          return done(new JsonWebTokenError(`secretOrPublicKey must be an asymmetric key when using ${header.alg}`));
        }
        if (!options.allowInvalidAsymmetricKeyTypes) {
          try {
            validateAsymmetricKey(header.alg, secretOrPublicKey2);
          } catch (e) {
            return done(e);
          }
        }
        let valid;
        try {
          valid = jws.verify(jwtString, decodedToken.header.alg, secretOrPublicKey2);
        } catch (e) {
          return done(e);
        }
        if (!valid) {
          return done(new JsonWebTokenError("invalid signature"));
        }
        const payload = decodedToken.payload;
        if (typeof payload.nbf !== "undefined" && !options.ignoreNotBefore) {
          if (typeof payload.nbf !== "number") {
            return done(new JsonWebTokenError("invalid nbf value"));
          }
          if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
            return done(new NotBeforeError("jwt not active", new Date(payload.nbf * 1e3)));
          }
        }
        if (typeof payload.exp !== "undefined" && !options.ignoreExpiration) {
          if (typeof payload.exp !== "number") {
            return done(new JsonWebTokenError("invalid exp value"));
          }
          if (clockTimestamp >= payload.exp + (options.clockTolerance || 0)) {
            return done(new TokenExpiredError("jwt expired", new Date(payload.exp * 1e3)));
          }
        }
        if (options.audience) {
          const audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
          const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
          const match = target.some(function(targetAudience) {
            return audiences.some(function(audience) {
              return audience instanceof RegExp ? audience.test(targetAudience) : audience === targetAudience;
            });
          });
          if (!match) {
            return done(new JsonWebTokenError("jwt audience invalid. expected: " + audiences.join(" or ")));
          }
        }
        if (options.issuer) {
          const invalid_issuer = typeof options.issuer === "string" && payload.iss !== options.issuer || Array.isArray(options.issuer) && options.issuer.indexOf(payload.iss) === -1;
          if (invalid_issuer) {
            return done(new JsonWebTokenError("jwt issuer invalid. expected: " + options.issuer));
          }
        }
        if (options.subject) {
          if (payload.sub !== options.subject) {
            return done(new JsonWebTokenError("jwt subject invalid. expected: " + options.subject));
          }
        }
        if (options.jwtid) {
          if (payload.jti !== options.jwtid) {
            return done(new JsonWebTokenError("jwt jwtid invalid. expected: " + options.jwtid));
          }
        }
        if (options.nonce) {
          if (payload.nonce !== options.nonce) {
            return done(new JsonWebTokenError("jwt nonce invalid. expected: " + options.nonce));
          }
        }
        if (options.maxAge) {
          if (typeof payload.iat !== "number") {
            return done(new JsonWebTokenError("iat required when maxAge is specified"));
          }
          const maxAgeTimestamp = timespan(options.maxAge, payload.iat);
          if (typeof maxAgeTimestamp === "undefined") {
            return done(new JsonWebTokenError('"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
          }
          if (clockTimestamp >= maxAgeTimestamp + (options.clockTolerance || 0)) {
            return done(new TokenExpiredError("maxAge exceeded", new Date(maxAgeTimestamp * 1e3)));
          }
        }
        if (options.complete === true) {
          const signature = decodedToken.signature;
          return done(null, {
            header,
            payload,
            signature
          });
        }
        return done(null, payload);
      });
    };
  }
});

// node_modules/lodash.includes/index.js
var require_lodash = __commonJS({
  "node_modules/lodash.includes/index.js"(exports2, module2) {
    var INFINITY = 1 / 0;
    var MAX_SAFE_INTEGER = 9007199254740991;
    var MAX_INTEGER = 17976931348623157e292;
    var NAN = 0 / 0;
    var argsTag = "[object Arguments]";
    var funcTag = "[object Function]";
    var genTag = "[object GeneratorFunction]";
    var stringTag = "[object String]";
    var symbolTag = "[object Symbol]";
    var reTrim = /^\s+|\s+$/g;
    var reIsBadHex = /^[-+]0x[0-9a-f]+$/i;
    var reIsBinary = /^0b[01]+$/i;
    var reIsOctal = /^0o[0-7]+$/i;
    var reIsUint = /^(?:0|[1-9]\d*)$/;
    var freeParseInt = parseInt;
    function arrayMap(array, iteratee) {
      var index = -1, length = array ? array.length : 0, result = Array(length);
      while (++index < length) {
        result[index] = iteratee(array[index], index, array);
      }
      return result;
    }
    function baseFindIndex(array, predicate, fromIndex, fromRight) {
      var length = array.length, index = fromIndex + (fromRight ? 1 : -1);
      while (fromRight ? index-- : ++index < length) {
        if (predicate(array[index], index, array)) {
          return index;
        }
      }
      return -1;
    }
    function baseIndexOf(array, value, fromIndex) {
      if (value !== value) {
        return baseFindIndex(array, baseIsNaN, fromIndex);
      }
      var index = fromIndex - 1, length = array.length;
      while (++index < length) {
        if (array[index] === value) {
          return index;
        }
      }
      return -1;
    }
    function baseIsNaN(value) {
      return value !== value;
    }
    function baseTimes(n, iteratee) {
      var index = -1, result = Array(n);
      while (++index < n) {
        result[index] = iteratee(index);
      }
      return result;
    }
    function baseValues(object, props) {
      return arrayMap(props, function(key) {
        return object[key];
      });
    }
    function overArg(func, transform) {
      return function(arg) {
        return func(transform(arg));
      };
    }
    var objectProto = Object.prototype;
    var hasOwnProperty = objectProto.hasOwnProperty;
    var objectToString = objectProto.toString;
    var propertyIsEnumerable = objectProto.propertyIsEnumerable;
    var nativeKeys = overArg(Object.keys, Object);
    var nativeMax = Math.max;
    function arrayLikeKeys(value, inherited) {
      var result = isArray(value) || isArguments(value) ? baseTimes(value.length, String) : [];
      var length = result.length, skipIndexes = !!length;
      for (var key in value) {
        if ((inherited || hasOwnProperty.call(value, key)) && !(skipIndexes && (key == "length" || isIndex(key, length)))) {
          result.push(key);
        }
      }
      return result;
    }
    function baseKeys(object) {
      if (!isPrototype(object)) {
        return nativeKeys(object);
      }
      var result = [];
      for (var key in Object(object)) {
        if (hasOwnProperty.call(object, key) && key != "constructor") {
          result.push(key);
        }
      }
      return result;
    }
    function isIndex(value, length) {
      length = length == null ? MAX_SAFE_INTEGER : length;
      return !!length && (typeof value == "number" || reIsUint.test(value)) && (value > -1 && value % 1 == 0 && value < length);
    }
    function isPrototype(value) {
      var Ctor = value && value.constructor, proto = typeof Ctor == "function" && Ctor.prototype || objectProto;
      return value === proto;
    }
    function includes(collection, value, fromIndex, guard) {
      collection = isArrayLike(collection) ? collection : values(collection);
      fromIndex = fromIndex && !guard ? toInteger(fromIndex) : 0;
      var length = collection.length;
      if (fromIndex < 0) {
        fromIndex = nativeMax(length + fromIndex, 0);
      }
      return isString(collection) ? fromIndex <= length && collection.indexOf(value, fromIndex) > -1 : !!length && baseIndexOf(collection, value, fromIndex) > -1;
    }
    function isArguments(value) {
      return isArrayLikeObject(value) && hasOwnProperty.call(value, "callee") && (!propertyIsEnumerable.call(value, "callee") || objectToString.call(value) == argsTag);
    }
    var isArray = Array.isArray;
    function isArrayLike(value) {
      return value != null && isLength(value.length) && !isFunction(value);
    }
    function isArrayLikeObject(value) {
      return isObjectLike(value) && isArrayLike(value);
    }
    function isFunction(value) {
      var tag = isObject(value) ? objectToString.call(value) : "";
      return tag == funcTag || tag == genTag;
    }
    function isLength(value) {
      return typeof value == "number" && value > -1 && value % 1 == 0 && value <= MAX_SAFE_INTEGER;
    }
    function isObject(value) {
      var type = typeof value;
      return !!value && (type == "object" || type == "function");
    }
    function isObjectLike(value) {
      return !!value && typeof value == "object";
    }
    function isString(value) {
      return typeof value == "string" || !isArray(value) && isObjectLike(value) && objectToString.call(value) == stringTag;
    }
    function isSymbol(value) {
      return typeof value == "symbol" || isObjectLike(value) && objectToString.call(value) == symbolTag;
    }
    function toFinite(value) {
      if (!value) {
        return value === 0 ? value : 0;
      }
      value = toNumber(value);
      if (value === INFINITY || value === -INFINITY) {
        var sign = value < 0 ? -1 : 1;
        return sign * MAX_INTEGER;
      }
      return value === value ? value : 0;
    }
    function toInteger(value) {
      var result = toFinite(value), remainder = result % 1;
      return result === result ? remainder ? result - remainder : result : 0;
    }
    function toNumber(value) {
      if (typeof value == "number") {
        return value;
      }
      if (isSymbol(value)) {
        return NAN;
      }
      if (isObject(value)) {
        var other = typeof value.valueOf == "function" ? value.valueOf() : value;
        value = isObject(other) ? other + "" : other;
      }
      if (typeof value != "string") {
        return value === 0 ? value : +value;
      }
      value = value.replace(reTrim, "");
      var isBinary = reIsBinary.test(value);
      return isBinary || reIsOctal.test(value) ? freeParseInt(value.slice(2), isBinary ? 2 : 8) : reIsBadHex.test(value) ? NAN : +value;
    }
    function keys(object) {
      return isArrayLike(object) ? arrayLikeKeys(object) : baseKeys(object);
    }
    function values(object) {
      return object ? baseValues(object, keys(object)) : [];
    }
    module2.exports = includes;
  }
});

// node_modules/lodash.isboolean/index.js
var require_lodash2 = __commonJS({
  "node_modules/lodash.isboolean/index.js"(exports2, module2) {
    var boolTag = "[object Boolean]";
    var objectProto = Object.prototype;
    var objectToString = objectProto.toString;
    function isBoolean(value) {
      return value === true || value === false || isObjectLike(value) && objectToString.call(value) == boolTag;
    }
    function isObjectLike(value) {
      return !!value && typeof value == "object";
    }
    module2.exports = isBoolean;
  }
});

// node_modules/lodash.isinteger/index.js
var require_lodash3 = __commonJS({
  "node_modules/lodash.isinteger/index.js"(exports2, module2) {
    var INFINITY = 1 / 0;
    var MAX_INTEGER = 17976931348623157e292;
    var NAN = 0 / 0;
    var symbolTag = "[object Symbol]";
    var reTrim = /^\s+|\s+$/g;
    var reIsBadHex = /^[-+]0x[0-9a-f]+$/i;
    var reIsBinary = /^0b[01]+$/i;
    var reIsOctal = /^0o[0-7]+$/i;
    var freeParseInt = parseInt;
    var objectProto = Object.prototype;
    var objectToString = objectProto.toString;
    function isInteger(value) {
      return typeof value == "number" && value == toInteger(value);
    }
    function isObject(value) {
      var type = typeof value;
      return !!value && (type == "object" || type == "function");
    }
    function isObjectLike(value) {
      return !!value && typeof value == "object";
    }
    function isSymbol(value) {
      return typeof value == "symbol" || isObjectLike(value) && objectToString.call(value) == symbolTag;
    }
    function toFinite(value) {
      if (!value) {
        return value === 0 ? value : 0;
      }
      value = toNumber(value);
      if (value === INFINITY || value === -INFINITY) {
        var sign = value < 0 ? -1 : 1;
        return sign * MAX_INTEGER;
      }
      return value === value ? value : 0;
    }
    function toInteger(value) {
      var result = toFinite(value), remainder = result % 1;
      return result === result ? remainder ? result - remainder : result : 0;
    }
    function toNumber(value) {
      if (typeof value == "number") {
        return value;
      }
      if (isSymbol(value)) {
        return NAN;
      }
      if (isObject(value)) {
        var other = typeof value.valueOf == "function" ? value.valueOf() : value;
        value = isObject(other) ? other + "" : other;
      }
      if (typeof value != "string") {
        return value === 0 ? value : +value;
      }
      value = value.replace(reTrim, "");
      var isBinary = reIsBinary.test(value);
      return isBinary || reIsOctal.test(value) ? freeParseInt(value.slice(2), isBinary ? 2 : 8) : reIsBadHex.test(value) ? NAN : +value;
    }
    module2.exports = isInteger;
  }
});

// node_modules/lodash.isnumber/index.js
var require_lodash4 = __commonJS({
  "node_modules/lodash.isnumber/index.js"(exports2, module2) {
    var numberTag = "[object Number]";
    var objectProto = Object.prototype;
    var objectToString = objectProto.toString;
    function isObjectLike(value) {
      return !!value && typeof value == "object";
    }
    function isNumber(value) {
      return typeof value == "number" || isObjectLike(value) && objectToString.call(value) == numberTag;
    }
    module2.exports = isNumber;
  }
});

// node_modules/lodash.isplainobject/index.js
var require_lodash5 = __commonJS({
  "node_modules/lodash.isplainobject/index.js"(exports2, module2) {
    var objectTag = "[object Object]";
    function isHostObject(value) {
      var result = false;
      if (value != null && typeof value.toString != "function") {
        try {
          result = !!(value + "");
        } catch (e) {
        }
      }
      return result;
    }
    function overArg(func, transform) {
      return function(arg) {
        return func(transform(arg));
      };
    }
    var funcProto = Function.prototype;
    var objectProto = Object.prototype;
    var funcToString = funcProto.toString;
    var hasOwnProperty = objectProto.hasOwnProperty;
    var objectCtorString = funcToString.call(Object);
    var objectToString = objectProto.toString;
    var getPrototype = overArg(Object.getPrototypeOf, Object);
    function isObjectLike(value) {
      return !!value && typeof value == "object";
    }
    function isPlainObject(value) {
      if (!isObjectLike(value) || objectToString.call(value) != objectTag || isHostObject(value)) {
        return false;
      }
      var proto = getPrototype(value);
      if (proto === null) {
        return true;
      }
      var Ctor = hasOwnProperty.call(proto, "constructor") && proto.constructor;
      return typeof Ctor == "function" && Ctor instanceof Ctor && funcToString.call(Ctor) == objectCtorString;
    }
    module2.exports = isPlainObject;
  }
});

// node_modules/lodash.isstring/index.js
var require_lodash6 = __commonJS({
  "node_modules/lodash.isstring/index.js"(exports2, module2) {
    var stringTag = "[object String]";
    var objectProto = Object.prototype;
    var objectToString = objectProto.toString;
    var isArray = Array.isArray;
    function isObjectLike(value) {
      return !!value && typeof value == "object";
    }
    function isString(value) {
      return typeof value == "string" || !isArray(value) && isObjectLike(value) && objectToString.call(value) == stringTag;
    }
    module2.exports = isString;
  }
});

// node_modules/lodash.once/index.js
var require_lodash7 = __commonJS({
  "node_modules/lodash.once/index.js"(exports2, module2) {
    var FUNC_ERROR_TEXT = "Expected a function";
    var INFINITY = 1 / 0;
    var MAX_INTEGER = 17976931348623157e292;
    var NAN = 0 / 0;
    var symbolTag = "[object Symbol]";
    var reTrim = /^\s+|\s+$/g;
    var reIsBadHex = /^[-+]0x[0-9a-f]+$/i;
    var reIsBinary = /^0b[01]+$/i;
    var reIsOctal = /^0o[0-7]+$/i;
    var freeParseInt = parseInt;
    var objectProto = Object.prototype;
    var objectToString = objectProto.toString;
    function before(n, func) {
      var result;
      if (typeof func != "function") {
        throw new TypeError(FUNC_ERROR_TEXT);
      }
      n = toInteger(n);
      return function() {
        if (--n > 0) {
          result = func.apply(this, arguments);
        }
        if (n <= 1) {
          func = void 0;
        }
        return result;
      };
    }
    function once(func) {
      return before(2, func);
    }
    function isObject(value) {
      var type = typeof value;
      return !!value && (type == "object" || type == "function");
    }
    function isObjectLike(value) {
      return !!value && typeof value == "object";
    }
    function isSymbol(value) {
      return typeof value == "symbol" || isObjectLike(value) && objectToString.call(value) == symbolTag;
    }
    function toFinite(value) {
      if (!value) {
        return value === 0 ? value : 0;
      }
      value = toNumber(value);
      if (value === INFINITY || value === -INFINITY) {
        var sign = value < 0 ? -1 : 1;
        return sign * MAX_INTEGER;
      }
      return value === value ? value : 0;
    }
    function toInteger(value) {
      var result = toFinite(value), remainder = result % 1;
      return result === result ? remainder ? result - remainder : result : 0;
    }
    function toNumber(value) {
      if (typeof value == "number") {
        return value;
      }
      if (isSymbol(value)) {
        return NAN;
      }
      if (isObject(value)) {
        var other = typeof value.valueOf == "function" ? value.valueOf() : value;
        value = isObject(other) ? other + "" : other;
      }
      if (typeof value != "string") {
        return value === 0 ? value : +value;
      }
      value = value.replace(reTrim, "");
      var isBinary = reIsBinary.test(value);
      return isBinary || reIsOctal.test(value) ? freeParseInt(value.slice(2), isBinary ? 2 : 8) : reIsBadHex.test(value) ? NAN : +value;
    }
    module2.exports = once;
  }
});

// node_modules/jsonwebtoken/sign.js
var require_sign = __commonJS({
  "node_modules/jsonwebtoken/sign.js"(exports2, module2) {
    var timespan = require_timespan();
    var PS_SUPPORTED = require_psSupported();
    var validateAsymmetricKey = require_validateAsymmetricKey();
    var jws = require_jws();
    var includes = require_lodash();
    var isBoolean = require_lodash2();
    var isInteger = require_lodash3();
    var isNumber = require_lodash4();
    var isPlainObject = require_lodash5();
    var isString = require_lodash6();
    var once = require_lodash7();
    var { KeyObject, createSecretKey, createPrivateKey } = require("crypto");
    var SUPPORTED_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "HS256", "HS384", "HS512", "none"];
    if (PS_SUPPORTED) {
      SUPPORTED_ALGS.splice(3, 0, "PS256", "PS384", "PS512");
    }
    var sign_options_schema = {
      expiresIn: { isValid: function(value) {
        return isInteger(value) || isString(value) && value;
      }, message: '"expiresIn" should be a number of seconds or string representing a timespan' },
      notBefore: { isValid: function(value) {
        return isInteger(value) || isString(value) && value;
      }, message: '"notBefore" should be a number of seconds or string representing a timespan' },
      audience: { isValid: function(value) {
        return isString(value) || Array.isArray(value);
      }, message: '"audience" must be a string or array' },
      algorithm: { isValid: includes.bind(null, SUPPORTED_ALGS), message: '"algorithm" must be a valid string enum value' },
      header: { isValid: isPlainObject, message: '"header" must be an object' },
      encoding: { isValid: isString, message: '"encoding" must be a string' },
      issuer: { isValid: isString, message: '"issuer" must be a string' },
      subject: { isValid: isString, message: '"subject" must be a string' },
      jwtid: { isValid: isString, message: '"jwtid" must be a string' },
      noTimestamp: { isValid: isBoolean, message: '"noTimestamp" must be a boolean' },
      keyid: { isValid: isString, message: '"keyid" must be a string' },
      mutatePayload: { isValid: isBoolean, message: '"mutatePayload" must be a boolean' },
      allowInsecureKeySizes: { isValid: isBoolean, message: '"allowInsecureKeySizes" must be a boolean' },
      allowInvalidAsymmetricKeyTypes: { isValid: isBoolean, message: '"allowInvalidAsymmetricKeyTypes" must be a boolean' }
    };
    var registered_claims_schema = {
      iat: { isValid: isNumber, message: '"iat" should be a number of seconds' },
      exp: { isValid: isNumber, message: '"exp" should be a number of seconds' },
      nbf: { isValid: isNumber, message: '"nbf" should be a number of seconds' }
    };
    function validate2(schema, allowUnknown, object, parameterName) {
      if (!isPlainObject(object)) {
        throw new Error('Expected "' + parameterName + '" to be a plain object.');
      }
      Object.keys(object).forEach(function(key) {
        const validator = schema[key];
        if (!validator) {
          if (!allowUnknown) {
            throw new Error('"' + key + '" is not allowed in "' + parameterName + '"');
          }
          return;
        }
        if (!validator.isValid(object[key])) {
          throw new Error(validator.message);
        }
      });
    }
    function validateOptions(options) {
      return validate2(sign_options_schema, false, options, "options");
    }
    function validatePayload(payload) {
      return validate2(registered_claims_schema, true, payload, "payload");
    }
    var options_to_payload = {
      "audience": "aud",
      "issuer": "iss",
      "subject": "sub",
      "jwtid": "jti"
    };
    var options_for_objects = [
      "expiresIn",
      "notBefore",
      "noTimestamp",
      "audience",
      "issuer",
      "subject",
      "jwtid"
    ];
    module2.exports = function(payload, secretOrPrivateKey, options, callback) {
      if (typeof options === "function") {
        callback = options;
        options = {};
      } else {
        options = options || {};
      }
      const isObjectPayload = typeof payload === "object" && !Buffer.isBuffer(payload);
      const header = Object.assign({
        alg: options.algorithm || "HS256",
        typ: isObjectPayload ? "JWT" : void 0,
        kid: options.keyid
      }, options.header);
      function failure(err) {
        if (callback) {
          return callback(err);
        }
        throw err;
      }
      if (!secretOrPrivateKey && options.algorithm !== "none") {
        return failure(new Error("secretOrPrivateKey must have a value"));
      }
      if (secretOrPrivateKey != null && !(secretOrPrivateKey instanceof KeyObject)) {
        try {
          secretOrPrivateKey = createPrivateKey(secretOrPrivateKey);
        } catch (_) {
          try {
            secretOrPrivateKey = createSecretKey(typeof secretOrPrivateKey === "string" ? Buffer.from(secretOrPrivateKey) : secretOrPrivateKey);
          } catch (_2) {
            return failure(new Error("secretOrPrivateKey is not valid key material"));
          }
        }
      }
      if (header.alg.startsWith("HS") && secretOrPrivateKey.type !== "secret") {
        return failure(new Error(`secretOrPrivateKey must be a symmetric key when using ${header.alg}`));
      } else if (/^(?:RS|PS|ES)/.test(header.alg)) {
        if (secretOrPrivateKey.type !== "private") {
          return failure(new Error(`secretOrPrivateKey must be an asymmetric key when using ${header.alg}`));
        }
        if (!options.allowInsecureKeySizes && !header.alg.startsWith("ES") && secretOrPrivateKey.asymmetricKeyDetails !== void 0 && //KeyObject.asymmetricKeyDetails is supported in Node 15+
        secretOrPrivateKey.asymmetricKeyDetails.modulusLength < 2048) {
          return failure(new Error(`secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`));
        }
      }
      if (typeof payload === "undefined") {
        return failure(new Error("payload is required"));
      } else if (isObjectPayload) {
        try {
          validatePayload(payload);
        } catch (error) {
          return failure(error);
        }
        if (!options.mutatePayload) {
          payload = Object.assign({}, payload);
        }
      } else {
        const invalid_options = options_for_objects.filter(function(opt) {
          return typeof options[opt] !== "undefined";
        });
        if (invalid_options.length > 0) {
          return failure(new Error("invalid " + invalid_options.join(",") + " option for " + typeof payload + " payload"));
        }
      }
      if (typeof payload.exp !== "undefined" && typeof options.expiresIn !== "undefined") {
        return failure(new Error('Bad "options.expiresIn" option the payload already has an "exp" property.'));
      }
      if (typeof payload.nbf !== "undefined" && typeof options.notBefore !== "undefined") {
        return failure(new Error('Bad "options.notBefore" option the payload already has an "nbf" property.'));
      }
      try {
        validateOptions(options);
      } catch (error) {
        return failure(error);
      }
      if (!options.allowInvalidAsymmetricKeyTypes) {
        try {
          validateAsymmetricKey(header.alg, secretOrPrivateKey);
        } catch (error) {
          return failure(error);
        }
      }
      const timestamp = payload.iat || Math.floor(Date.now() / 1e3);
      if (options.noTimestamp) {
        delete payload.iat;
      } else if (isObjectPayload) {
        payload.iat = timestamp;
      }
      if (typeof options.notBefore !== "undefined") {
        try {
          payload.nbf = timespan(options.notBefore, timestamp);
        } catch (err) {
          return failure(err);
        }
        if (typeof payload.nbf === "undefined") {
          return failure(new Error('"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
        }
      }
      if (typeof options.expiresIn !== "undefined" && typeof payload === "object") {
        try {
          payload.exp = timespan(options.expiresIn, timestamp);
        } catch (err) {
          return failure(err);
        }
        if (typeof payload.exp === "undefined") {
          return failure(new Error('"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
        }
      }
      Object.keys(options_to_payload).forEach(function(key) {
        const claim = options_to_payload[key];
        if (typeof options[key] !== "undefined") {
          if (typeof payload[claim] !== "undefined") {
            return failure(new Error('Bad "options.' + key + '" option. The payload already has an "' + claim + '" property.'));
          }
          payload[claim] = options[key];
        }
      });
      const encoding = options.encoding || "utf8";
      if (typeof callback === "function") {
        callback = callback && once(callback);
        jws.createSign({
          header,
          privateKey: secretOrPrivateKey,
          payload,
          encoding
        }).once("error", callback).once("done", function(signature) {
          if (!options.allowInsecureKeySizes && /^(?:RS|PS)/.test(header.alg) && signature.length < 256) {
            return callback(new Error(`secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`));
          }
          callback(null, signature);
        });
      } else {
        let signature = jws.sign({ header, payload, secret: secretOrPrivateKey, encoding });
        if (!options.allowInsecureKeySizes && /^(?:RS|PS)/.test(header.alg) && signature.length < 256) {
          throw new Error(`secretOrPrivateKey has a minimum key size of 2048 bits for ${header.alg}`);
        }
        return signature;
      }
    };
  }
});

// node_modules/jsonwebtoken/index.js
var require_jsonwebtoken = __commonJS({
  "node_modules/jsonwebtoken/index.js"(exports2, module2) {
    module2.exports = {
      decode: require_decode(),
      verify: require_verify(),
      sign: require_sign(),
      JsonWebTokenError: require_JsonWebTokenError(),
      NotBeforeError: require_NotBeforeError(),
      TokenExpiredError: require_TokenExpiredError()
    };
  }
});

// node_modules/universal-github-app-jwt/dist-node/index.js
var require_dist_node19 = __commonJS({
  "node_modules/universal-github-app-jwt/dist-node/index.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    function _interopDefault(ex) {
      return ex && typeof ex === "object" && "default" in ex ? ex["default"] : ex;
    }
    var jsonwebtoken = _interopDefault(require_jsonwebtoken());
    async function getToken({
      privateKey,
      payload
    }) {
      return jsonwebtoken.sign(payload, privateKey, {
        algorithm: "RS256"
      });
    }
    async function githubAppJwt({
      id,
      privateKey,
      now = Math.floor(Date.now() / 1e3)
    }) {
      const nowWithSafetyMargin = now - 30;
      const expiration = nowWithSafetyMargin + 60 * 10;
      const payload = {
        iat: nowWithSafetyMargin,
        exp: expiration,
        iss: id
      };
      const token = await getToken({
        privateKey,
        payload
      });
      return {
        appId: id,
        expiration,
        token
      };
    }
    exports2.githubAppJwt = githubAppJwt;
  }
});

// node_modules/@octokit/auth-app/node_modules/lru-cache/dist/commonjs/index.js
var require_commonjs = __commonJS({
  "node_modules/@octokit/auth-app/node_modules/lru-cache/dist/commonjs/index.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.LRUCache = void 0;
    var perf = typeof performance === "object" && performance && typeof performance.now === "function" ? performance : Date;
    var warned = /* @__PURE__ */ new Set();
    var PROCESS = typeof process === "object" && !!process ? process : {};
    var emitWarning = (msg, type, code, fn) => {
      typeof PROCESS.emitWarning === "function" ? PROCESS.emitWarning(msg, type, code, fn) : console.error(`[${code}] ${type}: ${msg}`);
    };
    var AC = globalThis.AbortController;
    var AS = globalThis.AbortSignal;
    if (typeof AC === "undefined") {
      AS = class AbortSignal {
        onabort;
        _onabort = [];
        reason;
        aborted = false;
        addEventListener(_, fn) {
          this._onabort.push(fn);
        }
      };
      AC = class AbortController {
        constructor() {
          warnACPolyfill();
        }
        signal = new AS();
        abort(reason) {
          if (this.signal.aborted)
            return;
          this.signal.reason = reason;
          this.signal.aborted = true;
          for (const fn of this.signal._onabort) {
            fn(reason);
          }
          this.signal.onabort?.(reason);
        }
      };
      let printACPolyfillWarning = PROCESS.env?.LRU_CACHE_IGNORE_AC_WARNING !== "1";
      const warnACPolyfill = () => {
        if (!printACPolyfillWarning)
          return;
        printACPolyfillWarning = false;
        emitWarning("AbortController is not defined. If using lru-cache in node 14, load an AbortController polyfill from the `node-abort-controller` package. A minimal polyfill is provided for use by LRUCache.fetch(), but it should not be relied upon in other contexts (eg, passing it to other APIs that use AbortController/AbortSignal might have undesirable effects). You may disable this with LRU_CACHE_IGNORE_AC_WARNING=1 in the env.", "NO_ABORT_CONTROLLER", "ENOTSUP", warnACPolyfill);
      };
    }
    var shouldWarn = (code) => !warned.has(code);
    var TYPE = Symbol("type");
    var isPosInt = (n) => n && n === Math.floor(n) && n > 0 && isFinite(n);
    var getUintArray = (max) => !isPosInt(max) ? null : max <= Math.pow(2, 8) ? Uint8Array : max <= Math.pow(2, 16) ? Uint16Array : max <= Math.pow(2, 32) ? Uint32Array : max <= Number.MAX_SAFE_INTEGER ? ZeroArray : null;
    var ZeroArray = class extends Array {
      constructor(size) {
        super(size);
        this.fill(0);
      }
    };
    var Stack = class _Stack {
      heap;
      length;
      // private constructor
      static #constructing = false;
      static create(max) {
        const HeapCls = getUintArray(max);
        if (!HeapCls)
          return [];
        _Stack.#constructing = true;
        const s = new _Stack(max, HeapCls);
        _Stack.#constructing = false;
        return s;
      }
      constructor(max, HeapCls) {
        if (!_Stack.#constructing) {
          throw new TypeError("instantiate Stack using Stack.create(n)");
        }
        this.heap = new HeapCls(max);
        this.length = 0;
      }
      push(n) {
        this.heap[this.length++] = n;
      }
      pop() {
        return this.heap[--this.length];
      }
    };
    var LRUCache = class _LRUCache {
      // properties coming in from the options of these, only max and maxSize
      // really *need* to be protected. The rest can be modified, as they just
      // set defaults for various methods.
      #max;
      #maxSize;
      #dispose;
      #disposeAfter;
      #fetchMethod;
      /**
       * {@link LRUCache.OptionsBase.ttl}
       */
      ttl;
      /**
       * {@link LRUCache.OptionsBase.ttlResolution}
       */
      ttlResolution;
      /**
       * {@link LRUCache.OptionsBase.ttlAutopurge}
       */
      ttlAutopurge;
      /**
       * {@link LRUCache.OptionsBase.updateAgeOnGet}
       */
      updateAgeOnGet;
      /**
       * {@link LRUCache.OptionsBase.updateAgeOnHas}
       */
      updateAgeOnHas;
      /**
       * {@link LRUCache.OptionsBase.allowStale}
       */
      allowStale;
      /**
       * {@link LRUCache.OptionsBase.noDisposeOnSet}
       */
      noDisposeOnSet;
      /**
       * {@link LRUCache.OptionsBase.noUpdateTTL}
       */
      noUpdateTTL;
      /**
       * {@link LRUCache.OptionsBase.maxEntrySize}
       */
      maxEntrySize;
      /**
       * {@link LRUCache.OptionsBase.sizeCalculation}
       */
      sizeCalculation;
      /**
       * {@link LRUCache.OptionsBase.noDeleteOnFetchRejection}
       */
      noDeleteOnFetchRejection;
      /**
       * {@link LRUCache.OptionsBase.noDeleteOnStaleGet}
       */
      noDeleteOnStaleGet;
      /**
       * {@link LRUCache.OptionsBase.allowStaleOnFetchAbort}
       */
      allowStaleOnFetchAbort;
      /**
       * {@link LRUCache.OptionsBase.allowStaleOnFetchRejection}
       */
      allowStaleOnFetchRejection;
      /**
       * {@link LRUCache.OptionsBase.ignoreFetchAbort}
       */
      ignoreFetchAbort;
      // computed properties
      #size;
      #calculatedSize;
      #keyMap;
      #keyList;
      #valList;
      #next;
      #prev;
      #head;
      #tail;
      #free;
      #disposed;
      #sizes;
      #starts;
      #ttls;
      #hasDispose;
      #hasFetchMethod;
      #hasDisposeAfter;
      /**
       * Do not call this method unless you need to inspect the
       * inner workings of the cache.  If anything returned by this
       * object is modified in any way, strange breakage may occur.
       *
       * These fields are private for a reason!
       *
       * @internal
       */
      static unsafeExposeInternals(c) {
        return {
          // properties
          starts: c.#starts,
          ttls: c.#ttls,
          sizes: c.#sizes,
          keyMap: c.#keyMap,
          keyList: c.#keyList,
          valList: c.#valList,
          next: c.#next,
          prev: c.#prev,
          get head() {
            return c.#head;
          },
          get tail() {
            return c.#tail;
          },
          free: c.#free,
          // methods
          isBackgroundFetch: (p) => c.#isBackgroundFetch(p),
          backgroundFetch: (k, index, options, context) => c.#backgroundFetch(k, index, options, context),
          moveToTail: (index) => c.#moveToTail(index),
          indexes: (options) => c.#indexes(options),
          rindexes: (options) => c.#rindexes(options),
          isStale: (index) => c.#isStale(index)
        };
      }
      // Protected read-only members
      /**
       * {@link LRUCache.OptionsBase.max} (read-only)
       */
      get max() {
        return this.#max;
      }
      /**
       * {@link LRUCache.OptionsBase.maxSize} (read-only)
       */
      get maxSize() {
        return this.#maxSize;
      }
      /**
       * The total computed size of items in the cache (read-only)
       */
      get calculatedSize() {
        return this.#calculatedSize;
      }
      /**
       * The number of items stored in the cache (read-only)
       */
      get size() {
        return this.#size;
      }
      /**
       * {@link LRUCache.OptionsBase.fetchMethod} (read-only)
       */
      get fetchMethod() {
        return this.#fetchMethod;
      }
      /**
       * {@link LRUCache.OptionsBase.dispose} (read-only)
       */
      get dispose() {
        return this.#dispose;
      }
      /**
       * {@link LRUCache.OptionsBase.disposeAfter} (read-only)
       */
      get disposeAfter() {
        return this.#disposeAfter;
      }
      constructor(options) {
        const { max = 0, ttl, ttlResolution = 1, ttlAutopurge, updateAgeOnGet, updateAgeOnHas, allowStale, dispose, disposeAfter, noDisposeOnSet, noUpdateTTL, maxSize = 0, maxEntrySize = 0, sizeCalculation, fetchMethod, noDeleteOnFetchRejection, noDeleteOnStaleGet, allowStaleOnFetchRejection, allowStaleOnFetchAbort, ignoreFetchAbort } = options;
        if (max !== 0 && !isPosInt(max)) {
          throw new TypeError("max option must be a nonnegative integer");
        }
        const UintArray = max ? getUintArray(max) : Array;
        if (!UintArray) {
          throw new Error("invalid max value: " + max);
        }
        this.#max = max;
        this.#maxSize = maxSize;
        this.maxEntrySize = maxEntrySize || this.#maxSize;
        this.sizeCalculation = sizeCalculation;
        if (this.sizeCalculation) {
          if (!this.#maxSize && !this.maxEntrySize) {
            throw new TypeError("cannot set sizeCalculation without setting maxSize or maxEntrySize");
          }
          if (typeof this.sizeCalculation !== "function") {
            throw new TypeError("sizeCalculation set to non-function");
          }
        }
        if (fetchMethod !== void 0 && typeof fetchMethod !== "function") {
          throw new TypeError("fetchMethod must be a function if specified");
        }
        this.#fetchMethod = fetchMethod;
        this.#hasFetchMethod = !!fetchMethod;
        this.#keyMap = /* @__PURE__ */ new Map();
        this.#keyList = new Array(max).fill(void 0);
        this.#valList = new Array(max).fill(void 0);
        this.#next = new UintArray(max);
        this.#prev = new UintArray(max);
        this.#head = 0;
        this.#tail = 0;
        this.#free = Stack.create(max);
        this.#size = 0;
        this.#calculatedSize = 0;
        if (typeof dispose === "function") {
          this.#dispose = dispose;
        }
        if (typeof disposeAfter === "function") {
          this.#disposeAfter = disposeAfter;
          this.#disposed = [];
        } else {
          this.#disposeAfter = void 0;
          this.#disposed = void 0;
        }
        this.#hasDispose = !!this.#dispose;
        this.#hasDisposeAfter = !!this.#disposeAfter;
        this.noDisposeOnSet = !!noDisposeOnSet;
        this.noUpdateTTL = !!noUpdateTTL;
        this.noDeleteOnFetchRejection = !!noDeleteOnFetchRejection;
        this.allowStaleOnFetchRejection = !!allowStaleOnFetchRejection;
        this.allowStaleOnFetchAbort = !!allowStaleOnFetchAbort;
        this.ignoreFetchAbort = !!ignoreFetchAbort;
        if (this.maxEntrySize !== 0) {
          if (this.#maxSize !== 0) {
            if (!isPosInt(this.#maxSize)) {
              throw new TypeError("maxSize must be a positive integer if specified");
            }
          }
          if (!isPosInt(this.maxEntrySize)) {
            throw new TypeError("maxEntrySize must be a positive integer if specified");
          }
          this.#initializeSizeTracking();
        }
        this.allowStale = !!allowStale;
        this.noDeleteOnStaleGet = !!noDeleteOnStaleGet;
        this.updateAgeOnGet = !!updateAgeOnGet;
        this.updateAgeOnHas = !!updateAgeOnHas;
        this.ttlResolution = isPosInt(ttlResolution) || ttlResolution === 0 ? ttlResolution : 1;
        this.ttlAutopurge = !!ttlAutopurge;
        this.ttl = ttl || 0;
        if (this.ttl) {
          if (!isPosInt(this.ttl)) {
            throw new TypeError("ttl must be a positive integer if specified");
          }
          this.#initializeTTLTracking();
        }
        if (this.#max === 0 && this.ttl === 0 && this.#maxSize === 0) {
          throw new TypeError("At least one of max, maxSize, or ttl is required");
        }
        if (!this.ttlAutopurge && !this.#max && !this.#maxSize) {
          const code = "LRU_CACHE_UNBOUNDED";
          if (shouldWarn(code)) {
            warned.add(code);
            const msg = "TTL caching without ttlAutopurge, max, or maxSize can result in unbounded memory consumption.";
            emitWarning(msg, "UnboundedCacheWarning", code, _LRUCache);
          }
        }
      }
      /**
       * Return the remaining TTL time for a given entry key
       */
      getRemainingTTL(key) {
        return this.#keyMap.has(key) ? Infinity : 0;
      }
      #initializeTTLTracking() {
        const ttls = new ZeroArray(this.#max);
        const starts = new ZeroArray(this.#max);
        this.#ttls = ttls;
        this.#starts = starts;
        this.#setItemTTL = (index, ttl, start = perf.now()) => {
          starts[index] = ttl !== 0 ? start : 0;
          ttls[index] = ttl;
          if (ttl !== 0 && this.ttlAutopurge) {
            const t = setTimeout(() => {
              if (this.#isStale(index)) {
                this.delete(this.#keyList[index]);
              }
            }, ttl + 1);
            if (t.unref) {
              t.unref();
            }
          }
        };
        this.#updateItemAge = (index) => {
          starts[index] = ttls[index] !== 0 ? perf.now() : 0;
        };
        this.#statusTTL = (status, index) => {
          if (ttls[index]) {
            const ttl = ttls[index];
            const start = starts[index];
            if (!ttl || !start)
              return;
            status.ttl = ttl;
            status.start = start;
            status.now = cachedNow || getNow();
            const age = status.now - start;
            status.remainingTTL = ttl - age;
          }
        };
        let cachedNow = 0;
        const getNow = () => {
          const n = perf.now();
          if (this.ttlResolution > 0) {
            cachedNow = n;
            const t = setTimeout(() => cachedNow = 0, this.ttlResolution);
            if (t.unref) {
              t.unref();
            }
          }
          return n;
        };
        this.getRemainingTTL = (key) => {
          const index = this.#keyMap.get(key);
          if (index === void 0) {
            return 0;
          }
          const ttl = ttls[index];
          const start = starts[index];
          if (!ttl || !start) {
            return Infinity;
          }
          const age = (cachedNow || getNow()) - start;
          return ttl - age;
        };
        this.#isStale = (index) => {
          const s = starts[index];
          const t = ttls[index];
          return !!t && !!s && (cachedNow || getNow()) - s > t;
        };
      }
      // conditionally set private methods related to TTL
      #updateItemAge = () => {
      };
      #statusTTL = () => {
      };
      #setItemTTL = () => {
      };
      /* c8 ignore stop */
      #isStale = () => false;
      #initializeSizeTracking() {
        const sizes = new ZeroArray(this.#max);
        this.#calculatedSize = 0;
        this.#sizes = sizes;
        this.#removeItemSize = (index) => {
          this.#calculatedSize -= sizes[index];
          sizes[index] = 0;
        };
        this.#requireSize = (k, v, size, sizeCalculation) => {
          if (this.#isBackgroundFetch(v)) {
            return 0;
          }
          if (!isPosInt(size)) {
            if (sizeCalculation) {
              if (typeof sizeCalculation !== "function") {
                throw new TypeError("sizeCalculation must be a function");
              }
              size = sizeCalculation(v, k);
              if (!isPosInt(size)) {
                throw new TypeError("sizeCalculation return invalid (expect positive integer)");
              }
            } else {
              throw new TypeError("invalid size value (must be positive integer). When maxSize or maxEntrySize is used, sizeCalculation or size must be set.");
            }
          }
          return size;
        };
        this.#addItemSize = (index, size, status) => {
          sizes[index] = size;
          if (this.#maxSize) {
            const maxSize = this.#maxSize - sizes[index];
            while (this.#calculatedSize > maxSize) {
              this.#evict(true);
            }
          }
          this.#calculatedSize += sizes[index];
          if (status) {
            status.entrySize = size;
            status.totalCalculatedSize = this.#calculatedSize;
          }
        };
      }
      #removeItemSize = (_i) => {
      };
      #addItemSize = (_i, _s, _st) => {
      };
      #requireSize = (_k, _v, size, sizeCalculation) => {
        if (size || sizeCalculation) {
          throw new TypeError("cannot set size without setting maxSize or maxEntrySize on cache");
        }
        return 0;
      };
      *#indexes({ allowStale = this.allowStale } = {}) {
        if (this.#size) {
          for (let i = this.#tail; true; ) {
            if (!this.#isValidIndex(i)) {
              break;
            }
            if (allowStale || !this.#isStale(i)) {
              yield i;
            }
            if (i === this.#head) {
              break;
            } else {
              i = this.#prev[i];
            }
          }
        }
      }
      *#rindexes({ allowStale = this.allowStale } = {}) {
        if (this.#size) {
          for (let i = this.#head; true; ) {
            if (!this.#isValidIndex(i)) {
              break;
            }
            if (allowStale || !this.#isStale(i)) {
              yield i;
            }
            if (i === this.#tail) {
              break;
            } else {
              i = this.#next[i];
            }
          }
        }
      }
      #isValidIndex(index) {
        return index !== void 0 && this.#keyMap.get(this.#keyList[index]) === index;
      }
      /**
       * Return a generator yielding `[key, value]` pairs,
       * in order from most recently used to least recently used.
       */
      *entries() {
        for (const i of this.#indexes()) {
          if (this.#valList[i] !== void 0 && this.#keyList[i] !== void 0 && !this.#isBackgroundFetch(this.#valList[i])) {
            yield [this.#keyList[i], this.#valList[i]];
          }
        }
      }
      /**
       * Inverse order version of {@link LRUCache.entries}
       *
       * Return a generator yielding `[key, value]` pairs,
       * in order from least recently used to most recently used.
       */
      *rentries() {
        for (const i of this.#rindexes()) {
          if (this.#valList[i] !== void 0 && this.#keyList[i] !== void 0 && !this.#isBackgroundFetch(this.#valList[i])) {
            yield [this.#keyList[i], this.#valList[i]];
          }
        }
      }
      /**
       * Return a generator yielding the keys in the cache,
       * in order from most recently used to least recently used.
       */
      *keys() {
        for (const i of this.#indexes()) {
          const k = this.#keyList[i];
          if (k !== void 0 && !this.#isBackgroundFetch(this.#valList[i])) {
            yield k;
          }
        }
      }
      /**
       * Inverse order version of {@link LRUCache.keys}
       *
       * Return a generator yielding the keys in the cache,
       * in order from least recently used to most recently used.
       */
      *rkeys() {
        for (const i of this.#rindexes()) {
          const k = this.#keyList[i];
          if (k !== void 0 && !this.#isBackgroundFetch(this.#valList[i])) {
            yield k;
          }
        }
      }
      /**
       * Return a generator yielding the values in the cache,
       * in order from most recently used to least recently used.
       */
      *values() {
        for (const i of this.#indexes()) {
          const v = this.#valList[i];
          if (v !== void 0 && !this.#isBackgroundFetch(this.#valList[i])) {
            yield this.#valList[i];
          }
        }
      }
      /**
       * Inverse order version of {@link LRUCache.values}
       *
       * Return a generator yielding the values in the cache,
       * in order from least recently used to most recently used.
       */
      *rvalues() {
        for (const i of this.#rindexes()) {
          const v = this.#valList[i];
          if (v !== void 0 && !this.#isBackgroundFetch(this.#valList[i])) {
            yield this.#valList[i];
          }
        }
      }
      /**
       * Iterating over the cache itself yields the same results as
       * {@link LRUCache.entries}
       */
      [Symbol.iterator]() {
        return this.entries();
      }
      /**
       * Find a value for which the supplied fn method returns a truthy value,
       * similar to Array.find().  fn is called as fn(value, key, cache).
       */
      find(fn, getOptions = {}) {
        for (const i of this.#indexes()) {
          const v = this.#valList[i];
          const value = this.#isBackgroundFetch(v) ? v.__staleWhileFetching : v;
          if (value === void 0)
            continue;
          if (fn(value, this.#keyList[i], this)) {
            return this.get(this.#keyList[i], getOptions);
          }
        }
      }
      /**
       * Call the supplied function on each item in the cache, in order from
       * most recently used to least recently used.  fn is called as
       * fn(value, key, cache).  Does not update age or recenty of use.
       * Does not iterate over stale values.
       */
      forEach(fn, thisp = this) {
        for (const i of this.#indexes()) {
          const v = this.#valList[i];
          const value = this.#isBackgroundFetch(v) ? v.__staleWhileFetching : v;
          if (value === void 0)
            continue;
          fn.call(thisp, value, this.#keyList[i], this);
        }
      }
      /**
       * The same as {@link LRUCache.forEach} but items are iterated over in
       * reverse order.  (ie, less recently used items are iterated over first.)
       */
      rforEach(fn, thisp = this) {
        for (const i of this.#rindexes()) {
          const v = this.#valList[i];
          const value = this.#isBackgroundFetch(v) ? v.__staleWhileFetching : v;
          if (value === void 0)
            continue;
          fn.call(thisp, value, this.#keyList[i], this);
        }
      }
      /**
       * Delete any stale entries. Returns true if anything was removed,
       * false otherwise.
       */
      purgeStale() {
        let deleted = false;
        for (const i of this.#rindexes({ allowStale: true })) {
          if (this.#isStale(i)) {
            this.delete(this.#keyList[i]);
            deleted = true;
          }
        }
        return deleted;
      }
      /**
       * Get the extended info about a given entry, to get its value, size, and
       * TTL info simultaneously. Like {@link LRUCache#dump}, but just for a
       * single key. Always returns stale values, if their info is found in the
       * cache, so be sure to check for expired TTLs if relevant.
       */
      info(key) {
        const i = this.#keyMap.get(key);
        if (i === void 0)
          return void 0;
        const v = this.#valList[i];
        const value = this.#isBackgroundFetch(v) ? v.__staleWhileFetching : v;
        if (value === void 0)
          return void 0;
        const entry = { value };
        if (this.#ttls && this.#starts) {
          const ttl = this.#ttls[i];
          const start = this.#starts[i];
          if (ttl && start) {
            const remain = ttl - (perf.now() - start);
            entry.ttl = remain;
            entry.start = Date.now();
          }
        }
        if (this.#sizes) {
          entry.size = this.#sizes[i];
        }
        return entry;
      }
      /**
       * Return an array of [key, {@link LRUCache.Entry}] tuples which can be
       * passed to cache.load()
       */
      dump() {
        const arr = [];
        for (const i of this.#indexes({ allowStale: true })) {
          const key = this.#keyList[i];
          const v = this.#valList[i];
          const value = this.#isBackgroundFetch(v) ? v.__staleWhileFetching : v;
          if (value === void 0 || key === void 0)
            continue;
          const entry = { value };
          if (this.#ttls && this.#starts) {
            entry.ttl = this.#ttls[i];
            const age = perf.now() - this.#starts[i];
            entry.start = Math.floor(Date.now() - age);
          }
          if (this.#sizes) {
            entry.size = this.#sizes[i];
          }
          arr.unshift([key, entry]);
        }
        return arr;
      }
      /**
       * Reset the cache and load in the items in entries in the order listed.
       * Note that the shape of the resulting cache may be different if the
       * same options are not used in both caches.
       */
      load(arr) {
        this.clear();
        for (const [key, entry] of arr) {
          if (entry.start) {
            const age = Date.now() - entry.start;
            entry.start = perf.now() - age;
          }
          this.set(key, entry.value, entry);
        }
      }
      /**
       * Add a value to the cache.
       *
       * Note: if `undefined` is specified as a value, this is an alias for
       * {@link LRUCache#delete}
       */
      set(k, v, setOptions = {}) {
        if (v === void 0) {
          this.delete(k);
          return this;
        }
        const { ttl = this.ttl, start, noDisposeOnSet = this.noDisposeOnSet, sizeCalculation = this.sizeCalculation, status } = setOptions;
        let { noUpdateTTL = this.noUpdateTTL } = setOptions;
        const size = this.#requireSize(k, v, setOptions.size || 0, sizeCalculation);
        if (this.maxEntrySize && size > this.maxEntrySize) {
          if (status) {
            status.set = "miss";
            status.maxEntrySizeExceeded = true;
          }
          this.delete(k);
          return this;
        }
        let index = this.#size === 0 ? void 0 : this.#keyMap.get(k);
        if (index === void 0) {
          index = this.#size === 0 ? this.#tail : this.#free.length !== 0 ? this.#free.pop() : this.#size === this.#max ? this.#evict(false) : this.#size;
          this.#keyList[index] = k;
          this.#valList[index] = v;
          this.#keyMap.set(k, index);
          this.#next[this.#tail] = index;
          this.#prev[index] = this.#tail;
          this.#tail = index;
          this.#size++;
          this.#addItemSize(index, size, status);
          if (status)
            status.set = "add";
          noUpdateTTL = false;
        } else {
          this.#moveToTail(index);
          const oldVal = this.#valList[index];
          if (v !== oldVal) {
            if (this.#hasFetchMethod && this.#isBackgroundFetch(oldVal)) {
              oldVal.__abortController.abort(new Error("replaced"));
              const { __staleWhileFetching: s } = oldVal;
              if (s !== void 0 && !noDisposeOnSet) {
                if (this.#hasDispose) {
                  this.#dispose?.(s, k, "set");
                }
                if (this.#hasDisposeAfter) {
                  this.#disposed?.push([s, k, "set"]);
                }
              }
            } else if (!noDisposeOnSet) {
              if (this.#hasDispose) {
                this.#dispose?.(oldVal, k, "set");
              }
              if (this.#hasDisposeAfter) {
                this.#disposed?.push([oldVal, k, "set"]);
              }
            }
            this.#removeItemSize(index);
            this.#addItemSize(index, size, status);
            this.#valList[index] = v;
            if (status) {
              status.set = "replace";
              const oldValue = oldVal && this.#isBackgroundFetch(oldVal) ? oldVal.__staleWhileFetching : oldVal;
              if (oldValue !== void 0)
                status.oldValue = oldValue;
            }
          } else if (status) {
            status.set = "update";
          }
        }
        if (ttl !== 0 && !this.#ttls) {
          this.#initializeTTLTracking();
        }
        if (this.#ttls) {
          if (!noUpdateTTL) {
            this.#setItemTTL(index, ttl, start);
          }
          if (status)
            this.#statusTTL(status, index);
        }
        if (!noDisposeOnSet && this.#hasDisposeAfter && this.#disposed) {
          const dt = this.#disposed;
          let task;
          while (task = dt?.shift()) {
            this.#disposeAfter?.(...task);
          }
        }
        return this;
      }
      /**
       * Evict the least recently used item, returning its value or
       * `undefined` if cache is empty.
       */
      pop() {
        try {
          while (this.#size) {
            const val = this.#valList[this.#head];
            this.#evict(true);
            if (this.#isBackgroundFetch(val)) {
              if (val.__staleWhileFetching) {
                return val.__staleWhileFetching;
              }
            } else if (val !== void 0) {
              return val;
            }
          }
        } finally {
          if (this.#hasDisposeAfter && this.#disposed) {
            const dt = this.#disposed;
            let task;
            while (task = dt?.shift()) {
              this.#disposeAfter?.(...task);
            }
          }
        }
      }
      #evict(free) {
        const head = this.#head;
        const k = this.#keyList[head];
        const v = this.#valList[head];
        if (this.#hasFetchMethod && this.#isBackgroundFetch(v)) {
          v.__abortController.abort(new Error("evicted"));
        } else if (this.#hasDispose || this.#hasDisposeAfter) {
          if (this.#hasDispose) {
            this.#dispose?.(v, k, "evict");
          }
          if (this.#hasDisposeAfter) {
            this.#disposed?.push([v, k, "evict"]);
          }
        }
        this.#removeItemSize(head);
        if (free) {
          this.#keyList[head] = void 0;
          this.#valList[head] = void 0;
          this.#free.push(head);
        }
        if (this.#size === 1) {
          this.#head = this.#tail = 0;
          this.#free.length = 0;
        } else {
          this.#head = this.#next[head];
        }
        this.#keyMap.delete(k);
        this.#size--;
        return head;
      }
      /**
       * Check if a key is in the cache, without updating the recency of use.
       * Will return false if the item is stale, even though it is technically
       * in the cache.
       *
       * Will not update item age unless
       * {@link LRUCache.OptionsBase.updateAgeOnHas} is set.
       */
      has(k, hasOptions = {}) {
        const { updateAgeOnHas = this.updateAgeOnHas, status } = hasOptions;
        const index = this.#keyMap.get(k);
        if (index !== void 0) {
          const v = this.#valList[index];
          if (this.#isBackgroundFetch(v) && v.__staleWhileFetching === void 0) {
            return false;
          }
          if (!this.#isStale(index)) {
            if (updateAgeOnHas) {
              this.#updateItemAge(index);
            }
            if (status) {
              status.has = "hit";
              this.#statusTTL(status, index);
            }
            return true;
          } else if (status) {
            status.has = "stale";
            this.#statusTTL(status, index);
          }
        } else if (status) {
          status.has = "miss";
        }
        return false;
      }
      /**
       * Like {@link LRUCache#get} but doesn't update recency or delete stale
       * items.
       *
       * Returns `undefined` if the item is stale, unless
       * {@link LRUCache.OptionsBase.allowStale} is set.
       */
      peek(k, peekOptions = {}) {
        const { allowStale = this.allowStale } = peekOptions;
        const index = this.#keyMap.get(k);
        if (index === void 0 || !allowStale && this.#isStale(index)) {
          return;
        }
        const v = this.#valList[index];
        return this.#isBackgroundFetch(v) ? v.__staleWhileFetching : v;
      }
      #backgroundFetch(k, index, options, context) {
        const v = index === void 0 ? void 0 : this.#valList[index];
        if (this.#isBackgroundFetch(v)) {
          return v;
        }
        const ac = new AC();
        const { signal } = options;
        signal?.addEventListener("abort", () => ac.abort(signal.reason), {
          signal: ac.signal
        });
        const fetchOpts = {
          signal: ac.signal,
          options,
          context
        };
        const cb = (v2, updateCache = false) => {
          const { aborted } = ac.signal;
          const ignoreAbort = options.ignoreFetchAbort && v2 !== void 0;
          if (options.status) {
            if (aborted && !updateCache) {
              options.status.fetchAborted = true;
              options.status.fetchError = ac.signal.reason;
              if (ignoreAbort)
                options.status.fetchAbortIgnored = true;
            } else {
              options.status.fetchResolved = true;
            }
          }
          if (aborted && !ignoreAbort && !updateCache) {
            return fetchFail(ac.signal.reason);
          }
          const bf2 = p;
          if (this.#valList[index] === p) {
            if (v2 === void 0) {
              if (bf2.__staleWhileFetching) {
                this.#valList[index] = bf2.__staleWhileFetching;
              } else {
                this.delete(k);
              }
            } else {
              if (options.status)
                options.status.fetchUpdated = true;
              this.set(k, v2, fetchOpts.options);
            }
          }
          return v2;
        };
        const eb = (er) => {
          if (options.status) {
            options.status.fetchRejected = true;
            options.status.fetchError = er;
          }
          return fetchFail(er);
        };
        const fetchFail = (er) => {
          const { aborted } = ac.signal;
          const allowStaleAborted = aborted && options.allowStaleOnFetchAbort;
          const allowStale = allowStaleAborted || options.allowStaleOnFetchRejection;
          const noDelete = allowStale || options.noDeleteOnFetchRejection;
          const bf2 = p;
          if (this.#valList[index] === p) {
            const del = !noDelete || bf2.__staleWhileFetching === void 0;
            if (del) {
              this.delete(k);
            } else if (!allowStaleAborted) {
              this.#valList[index] = bf2.__staleWhileFetching;
            }
          }
          if (allowStale) {
            if (options.status && bf2.__staleWhileFetching !== void 0) {
              options.status.returnedStale = true;
            }
            return bf2.__staleWhileFetching;
          } else if (bf2.__returned === bf2) {
            throw er;
          }
        };
        const pcall = (res, rej) => {
          const fmp = this.#fetchMethod?.(k, v, fetchOpts);
          if (fmp && fmp instanceof Promise) {
            fmp.then((v2) => res(v2 === void 0 ? void 0 : v2), rej);
          }
          ac.signal.addEventListener("abort", () => {
            if (!options.ignoreFetchAbort || options.allowStaleOnFetchAbort) {
              res(void 0);
              if (options.allowStaleOnFetchAbort) {
                res = (v2) => cb(v2, true);
              }
            }
          });
        };
        if (options.status)
          options.status.fetchDispatched = true;
        const p = new Promise(pcall).then(cb, eb);
        const bf = Object.assign(p, {
          __abortController: ac,
          __staleWhileFetching: v,
          __returned: void 0
        });
        if (index === void 0) {
          this.set(k, bf, { ...fetchOpts.options, status: void 0 });
          index = this.#keyMap.get(k);
        } else {
          this.#valList[index] = bf;
        }
        return bf;
      }
      #isBackgroundFetch(p) {
        if (!this.#hasFetchMethod)
          return false;
        const b = p;
        return !!b && b instanceof Promise && b.hasOwnProperty("__staleWhileFetching") && b.__abortController instanceof AC;
      }
      async fetch(k, fetchOptions = {}) {
        const {
          // get options
          allowStale = this.allowStale,
          updateAgeOnGet = this.updateAgeOnGet,
          noDeleteOnStaleGet = this.noDeleteOnStaleGet,
          // set options
          ttl = this.ttl,
          noDisposeOnSet = this.noDisposeOnSet,
          size = 0,
          sizeCalculation = this.sizeCalculation,
          noUpdateTTL = this.noUpdateTTL,
          // fetch exclusive options
          noDeleteOnFetchRejection = this.noDeleteOnFetchRejection,
          allowStaleOnFetchRejection = this.allowStaleOnFetchRejection,
          ignoreFetchAbort = this.ignoreFetchAbort,
          allowStaleOnFetchAbort = this.allowStaleOnFetchAbort,
          context,
          forceRefresh = false,
          status,
          signal
        } = fetchOptions;
        if (!this.#hasFetchMethod) {
          if (status)
            status.fetch = "get";
          return this.get(k, {
            allowStale,
            updateAgeOnGet,
            noDeleteOnStaleGet,
            status
          });
        }
        const options = {
          allowStale,
          updateAgeOnGet,
          noDeleteOnStaleGet,
          ttl,
          noDisposeOnSet,
          size,
          sizeCalculation,
          noUpdateTTL,
          noDeleteOnFetchRejection,
          allowStaleOnFetchRejection,
          allowStaleOnFetchAbort,
          ignoreFetchAbort,
          status,
          signal
        };
        let index = this.#keyMap.get(k);
        if (index === void 0) {
          if (status)
            status.fetch = "miss";
          const p = this.#backgroundFetch(k, index, options, context);
          return p.__returned = p;
        } else {
          const v = this.#valList[index];
          if (this.#isBackgroundFetch(v)) {
            const stale = allowStale && v.__staleWhileFetching !== void 0;
            if (status) {
              status.fetch = "inflight";
              if (stale)
                status.returnedStale = true;
            }
            return stale ? v.__staleWhileFetching : v.__returned = v;
          }
          const isStale = this.#isStale(index);
          if (!forceRefresh && !isStale) {
            if (status)
              status.fetch = "hit";
            this.#moveToTail(index);
            if (updateAgeOnGet) {
              this.#updateItemAge(index);
            }
            if (status)
              this.#statusTTL(status, index);
            return v;
          }
          const p = this.#backgroundFetch(k, index, options, context);
          const hasStale = p.__staleWhileFetching !== void 0;
          const staleVal = hasStale && allowStale;
          if (status) {
            status.fetch = isStale ? "stale" : "refresh";
            if (staleVal && isStale)
              status.returnedStale = true;
          }
          return staleVal ? p.__staleWhileFetching : p.__returned = p;
        }
      }
      /**
       * Return a value from the cache. Will update the recency of the cache
       * entry found.
       *
       * If the key is not found, get() will return `undefined`.
       */
      get(k, getOptions = {}) {
        const { allowStale = this.allowStale, updateAgeOnGet = this.updateAgeOnGet, noDeleteOnStaleGet = this.noDeleteOnStaleGet, status } = getOptions;
        const index = this.#keyMap.get(k);
        if (index !== void 0) {
          const value = this.#valList[index];
          const fetching = this.#isBackgroundFetch(value);
          if (status)
            this.#statusTTL(status, index);
          if (this.#isStale(index)) {
            if (status)
              status.get = "stale";
            if (!fetching) {
              if (!noDeleteOnStaleGet) {
                this.delete(k);
              }
              if (status && allowStale)
                status.returnedStale = true;
              return allowStale ? value : void 0;
            } else {
              if (status && allowStale && value.__staleWhileFetching !== void 0) {
                status.returnedStale = true;
              }
              return allowStale ? value.__staleWhileFetching : void 0;
            }
          } else {
            if (status)
              status.get = "hit";
            if (fetching) {
              return value.__staleWhileFetching;
            }
            this.#moveToTail(index);
            if (updateAgeOnGet) {
              this.#updateItemAge(index);
            }
            return value;
          }
        } else if (status) {
          status.get = "miss";
        }
      }
      #connect(p, n) {
        this.#prev[n] = p;
        this.#next[p] = n;
      }
      #moveToTail(index) {
        if (index !== this.#tail) {
          if (index === this.#head) {
            this.#head = this.#next[index];
          } else {
            this.#connect(this.#prev[index], this.#next[index]);
          }
          this.#connect(this.#tail, index);
          this.#tail = index;
        }
      }
      /**
       * Deletes a key out of the cache.
       * Returns true if the key was deleted, false otherwise.
       */
      delete(k) {
        let deleted = false;
        if (this.#size !== 0) {
          const index = this.#keyMap.get(k);
          if (index !== void 0) {
            deleted = true;
            if (this.#size === 1) {
              this.clear();
            } else {
              this.#removeItemSize(index);
              const v = this.#valList[index];
              if (this.#isBackgroundFetch(v)) {
                v.__abortController.abort(new Error("deleted"));
              } else if (this.#hasDispose || this.#hasDisposeAfter) {
                if (this.#hasDispose) {
                  this.#dispose?.(v, k, "delete");
                }
                if (this.#hasDisposeAfter) {
                  this.#disposed?.push([v, k, "delete"]);
                }
              }
              this.#keyMap.delete(k);
              this.#keyList[index] = void 0;
              this.#valList[index] = void 0;
              if (index === this.#tail) {
                this.#tail = this.#prev[index];
              } else if (index === this.#head) {
                this.#head = this.#next[index];
              } else {
                const pi = this.#prev[index];
                this.#next[pi] = this.#next[index];
                const ni = this.#next[index];
                this.#prev[ni] = this.#prev[index];
              }
              this.#size--;
              this.#free.push(index);
            }
          }
        }
        if (this.#hasDisposeAfter && this.#disposed?.length) {
          const dt = this.#disposed;
          let task;
          while (task = dt?.shift()) {
            this.#disposeAfter?.(...task);
          }
        }
        return deleted;
      }
      /**
       * Clear the cache entirely, throwing away all values.
       */
      clear() {
        for (const index of this.#rindexes({ allowStale: true })) {
          const v = this.#valList[index];
          if (this.#isBackgroundFetch(v)) {
            v.__abortController.abort(new Error("deleted"));
          } else {
            const k = this.#keyList[index];
            if (this.#hasDispose) {
              this.#dispose?.(v, k, "delete");
            }
            if (this.#hasDisposeAfter) {
              this.#disposed?.push([v, k, "delete"]);
            }
          }
        }
        this.#keyMap.clear();
        this.#valList.fill(void 0);
        this.#keyList.fill(void 0);
        if (this.#ttls && this.#starts) {
          this.#ttls.fill(0);
          this.#starts.fill(0);
        }
        if (this.#sizes) {
          this.#sizes.fill(0);
        }
        this.#head = 0;
        this.#tail = 0;
        this.#free.length = 0;
        this.#calculatedSize = 0;
        this.#size = 0;
        if (this.#hasDisposeAfter && this.#disposed) {
          const dt = this.#disposed;
          let task;
          while (task = dt?.shift()) {
            this.#disposeAfter?.(...task);
          }
        }
      }
    };
    exports2.LRUCache = LRUCache;
  }
});

// node_modules/@octokit/auth-app/dist-node/index.js
var require_dist_node20 = __commonJS({
  "node_modules/@octokit/auth-app/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __create2 = Object.create;
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __getProtoOf2 = Object.getPrototypeOf;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toESM2 = (mod, isNodeMode, target) => (target = mod != null ? __create2(__getProtoOf2(mod)) : {}, __copyProps2(
      // If the importer is in node compatibility mode or this is not an ESM
      // file that has been converted to a CommonJS file using a Babel-
      // compatible transform (i.e. "__esModule" has not been set), then set
      // "default" to the CommonJS "module.exports" for node compatibility.
      isNodeMode || !mod || !mod.__esModule ? __defProp2(target, "default", { value: mod, enumerable: true }) : target,
      mod
    ));
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      createAppAuth: () => createAppAuth,
      createOAuthUserAuth: () => import_auth_oauth_user2.createOAuthUserAuth
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_universal_user_agent = require_dist_node();
    var import_request = require_dist_node5();
    var import_auth_oauth_app = require_dist_node18();
    var import_deprecation = require_dist_node3();
    var OAuthAppAuth = __toESM2(require_dist_node18());
    var import_universal_github_app_jwt = require_dist_node19();
    async function getAppAuthentication({
      appId,
      privateKey,
      timeDifference
    }) {
      try {
        const appAuthentication = await (0, import_universal_github_app_jwt.githubAppJwt)({
          id: +appId,
          privateKey,
          now: timeDifference && Math.floor(Date.now() / 1e3) + timeDifference
        });
        return {
          type: "app",
          token: appAuthentication.token,
          appId: appAuthentication.appId,
          expiresAt: new Date(appAuthentication.expiration * 1e3).toISOString()
        };
      } catch (error) {
        if (privateKey === "-----BEGIN RSA PRIVATE KEY-----") {
          throw new Error(
            "The 'privateKey` option contains only the first line '-----BEGIN RSA PRIVATE KEY-----'. If you are setting it using a `.env` file, make sure it is set on a single line with newlines replaced by '\n'"
          );
        } else {
          throw error;
        }
      }
    }
    var import_lru_cache = require_commonjs();
    function getCache() {
      return new import_lru_cache.LRUCache({
        // cache max. 15000 tokens, that will use less than 10mb memory
        max: 15e3,
        // Cache for 1 minute less than GitHub expiry
        ttl: 1e3 * 60 * 59
      });
    }
    async function get(cache, options) {
      const cacheKey = optionsToCacheKey(options);
      const result = await cache.get(cacheKey);
      if (!result) {
        return;
      }
      const [
        token,
        createdAt,
        expiresAt,
        repositorySelection,
        permissionsString,
        singleFileName
      ] = result.split("|");
      const permissions = options.permissions || permissionsString.split(/,/).reduce((permissions2, string) => {
        if (/!$/.test(string)) {
          permissions2[string.slice(0, -1)] = "write";
        } else {
          permissions2[string] = "read";
        }
        return permissions2;
      }, {});
      return {
        token,
        createdAt,
        expiresAt,
        permissions,
        repositoryIds: options.repositoryIds,
        repositoryNames: options.repositoryNames,
        singleFileName,
        repositorySelection
      };
    }
    async function set(cache, options, data) {
      const key = optionsToCacheKey(options);
      const permissionsString = options.permissions ? "" : Object.keys(data.permissions).map(
        (name) => `${name}${data.permissions[name] === "write" ? "!" : ""}`
      ).join(",");
      const value = [
        data.token,
        data.createdAt,
        data.expiresAt,
        data.repositorySelection,
        permissionsString,
        data.singleFileName
      ].join("|");
      await cache.set(key, value);
    }
    function optionsToCacheKey({
      installationId,
      permissions = {},
      repositoryIds = [],
      repositoryNames = []
    }) {
      const permissionsString = Object.keys(permissions).sort().map((name) => permissions[name] === "read" ? name : `${name}!`).join(",");
      const repositoryIdsString = repositoryIds.sort().join(",");
      const repositoryNamesString = repositoryNames.join(",");
      return [
        installationId,
        repositoryIdsString,
        repositoryNamesString,
        permissionsString
      ].filter(Boolean).join("|");
    }
    function toTokenAuthentication({
      installationId,
      token,
      createdAt,
      expiresAt,
      repositorySelection,
      permissions,
      repositoryIds,
      repositoryNames,
      singleFileName
    }) {
      return Object.assign(
        {
          type: "token",
          tokenType: "installation",
          token,
          installationId,
          permissions,
          createdAt,
          expiresAt,
          repositorySelection
        },
        repositoryIds ? { repositoryIds } : null,
        repositoryNames ? { repositoryNames } : null,
        singleFileName ? { singleFileName } : null
      );
    }
    async function getInstallationAuthentication(state, options, customRequest) {
      const installationId = Number(options.installationId || state.installationId);
      if (!installationId) {
        throw new Error(
          "[@octokit/auth-app] installationId option is required for installation authentication."
        );
      }
      if (options.factory) {
        const { type, factory, oauthApp, ...factoryAuthOptions } = {
          ...state,
          ...options
        };
        return factory(factoryAuthOptions);
      }
      const optionsWithInstallationTokenFromState = Object.assign(
        { installationId },
        options
      );
      if (!options.refresh) {
        const result = await get(
          state.cache,
          optionsWithInstallationTokenFromState
        );
        if (result) {
          const {
            token: token2,
            createdAt: createdAt2,
            expiresAt: expiresAt2,
            permissions: permissions2,
            repositoryIds: repositoryIds2,
            repositoryNames: repositoryNames2,
            singleFileName: singleFileName2,
            repositorySelection: repositorySelection2
          } = result;
          return toTokenAuthentication({
            installationId,
            token: token2,
            createdAt: createdAt2,
            expiresAt: expiresAt2,
            permissions: permissions2,
            repositorySelection: repositorySelection2,
            repositoryIds: repositoryIds2,
            repositoryNames: repositoryNames2,
            singleFileName: singleFileName2
          });
        }
      }
      const appAuthentication = await getAppAuthentication(state);
      const request = customRequest || state.request;
      const {
        data: {
          token,
          expires_at: expiresAt,
          repositories,
          permissions: permissionsOptional,
          repository_selection: repositorySelectionOptional,
          single_file: singleFileName
        }
      } = await request("POST /app/installations/{installation_id}/access_tokens", {
        installation_id: installationId,
        repository_ids: options.repositoryIds,
        repositories: options.repositoryNames,
        permissions: options.permissions,
        mediaType: {
          previews: ["machine-man"]
        },
        headers: {
          authorization: `bearer ${appAuthentication.token}`
        }
      });
      const permissions = permissionsOptional || {};
      const repositorySelection = repositorySelectionOptional || "all";
      const repositoryIds = repositories ? repositories.map((r) => r.id) : void 0;
      const repositoryNames = repositories ? repositories.map((repo) => repo.name) : void 0;
      const createdAt = (/* @__PURE__ */ new Date()).toISOString();
      await set(state.cache, optionsWithInstallationTokenFromState, {
        token,
        createdAt,
        expiresAt,
        repositorySelection,
        permissions,
        repositoryIds,
        repositoryNames,
        singleFileName
      });
      return toTokenAuthentication({
        installationId,
        token,
        createdAt,
        expiresAt,
        repositorySelection,
        permissions,
        repositoryIds,
        repositoryNames,
        singleFileName
      });
    }
    async function auth(state, authOptions) {
      switch (authOptions.type) {
        case "app":
          return getAppAuthentication(state);
        case "oauth":
          state.log.warn(
            // @ts-expect-error `log.warn()` expects string
            new import_deprecation.Deprecation(
              `[@octokit/auth-app] {type: "oauth"} is deprecated. Use {type: "oauth-app"} instead`
            )
          );
        case "oauth-app":
          return state.oauthApp({ type: "oauth-app" });
        case "installation":
          authOptions;
          return getInstallationAuthentication(state, {
            ...authOptions,
            type: "installation"
          });
        case "oauth-user":
          return state.oauthApp(authOptions);
        default:
          throw new Error(`Invalid auth type: ${authOptions.type}`);
      }
    }
    var import_auth_oauth_user = require_dist_node17();
    var import_request_error = require_dist_node4();
    var PATHS = [
      "/app",
      "/app/hook/config",
      "/app/hook/deliveries",
      "/app/hook/deliveries/{delivery_id}",
      "/app/hook/deliveries/{delivery_id}/attempts",
      "/app/installations",
      "/app/installations/{installation_id}",
      "/app/installations/{installation_id}/access_tokens",
      "/app/installations/{installation_id}/suspended",
      "/marketplace_listing/accounts/{account_id}",
      "/marketplace_listing/plan",
      "/marketplace_listing/plans",
      "/marketplace_listing/plans/{plan_id}/accounts",
      "/marketplace_listing/stubbed/accounts/{account_id}",
      "/marketplace_listing/stubbed/plan",
      "/marketplace_listing/stubbed/plans",
      "/marketplace_listing/stubbed/plans/{plan_id}/accounts",
      "/orgs/{org}/installation",
      "/repos/{owner}/{repo}/installation",
      "/users/{username}/installation"
    ];
    function routeMatcher(paths) {
      const regexes = paths.map(
        (p) => p.split("/").map((c) => c.startsWith("{") ? "(?:.+?)" : c).join("/")
      );
      const regex = `^(?:${regexes.map((r) => `(?:${r})`).join("|")})$`;
      return new RegExp(regex, "i");
    }
    var REGEX = routeMatcher(PATHS);
    function requiresAppAuth(url) {
      return !!url && REGEX.test(url.split("?")[0]);
    }
    var FIVE_SECONDS_IN_MS = 5 * 1e3;
    function isNotTimeSkewError(error) {
      return !(error.message.match(
        /'Expiration time' claim \('exp'\) must be a numeric value representing the future time at which the assertion expires/
      ) || error.message.match(
        /'Issued at' claim \('iat'\) must be an Integer representing the time that the assertion was issued/
      ));
    }
    async function hook(state, request, route, parameters) {
      const endpoint = request.endpoint.merge(route, parameters);
      const url = endpoint.url;
      if (/\/login\/oauth\/access_token$/.test(url)) {
        return request(endpoint);
      }
      if (requiresAppAuth(url.replace(request.endpoint.DEFAULTS.baseUrl, ""))) {
        const { token: token2 } = await getAppAuthentication(state);
        endpoint.headers.authorization = `bearer ${token2}`;
        let response;
        try {
          response = await request(endpoint);
        } catch (error) {
          if (isNotTimeSkewError(error)) {
            throw error;
          }
          if (typeof error.response.headers.date === "undefined") {
            throw error;
          }
          const diff = Math.floor(
            (Date.parse(error.response.headers.date) - Date.parse((/* @__PURE__ */ new Date()).toString())) / 1e3
          );
          state.log.warn(error.message);
          state.log.warn(
            `[@octokit/auth-app] GitHub API time and system time are different by ${diff} seconds. Retrying request with the difference accounted for.`
          );
          const { token: token3 } = await getAppAuthentication({
            ...state,
            timeDifference: diff
          });
          endpoint.headers.authorization = `bearer ${token3}`;
          return request(endpoint);
        }
        return response;
      }
      if ((0, import_auth_oauth_user.requiresBasicAuth)(url)) {
        const authentication = await state.oauthApp({ type: "oauth-app" });
        endpoint.headers.authorization = authentication.headers.authorization;
        return request(endpoint);
      }
      const { token, createdAt } = await getInstallationAuthentication(
        state,
        // @ts-expect-error TBD
        {},
        request
      );
      endpoint.headers.authorization = `token ${token}`;
      return sendRequestWithRetries(
        state,
        request,
        endpoint,
        createdAt
      );
    }
    async function sendRequestWithRetries(state, request, options, createdAt, retries = 0) {
      const timeSinceTokenCreationInMs = +/* @__PURE__ */ new Date() - +new Date(createdAt);
      try {
        return await request(options);
      } catch (error) {
        if (error.status !== 401) {
          throw error;
        }
        if (timeSinceTokenCreationInMs >= FIVE_SECONDS_IN_MS) {
          if (retries > 0) {
            error.message = `After ${retries} retries within ${timeSinceTokenCreationInMs / 1e3}s of creating the installation access token, the response remains 401. At this point, the cause may be an authentication problem or a system outage. Please check https://www.githubstatus.com for status information`;
          }
          throw error;
        }
        ++retries;
        const awaitTime = retries * 1e3;
        state.log.warn(
          `[@octokit/auth-app] Retrying after 401 response to account for token replication delay (retry: ${retries}, wait: ${awaitTime / 1e3}s)`
        );
        await new Promise((resolve) => setTimeout(resolve, awaitTime));
        return sendRequestWithRetries(state, request, options, createdAt, retries);
      }
    }
    var VERSION = "6.0.1";
    var import_auth_oauth_user2 = require_dist_node17();
    function createAppAuth(options) {
      if (!options.appId) {
        throw new Error("[@octokit/auth-app] appId option is required");
      }
      if (!Number.isFinite(+options.appId)) {
        throw new Error(
          "[@octokit/auth-app] appId option must be a number or numeric string"
        );
      }
      if (!options.privateKey) {
        throw new Error("[@octokit/auth-app] privateKey option is required");
      }
      if ("installationId" in options && !options.installationId) {
        throw new Error(
          "[@octokit/auth-app] installationId is set to a falsy value"
        );
      }
      const log = Object.assign(
        {
          warn: console.warn.bind(console)
        },
        options.log
      );
      const request = options.request || import_request.request.defaults({
        headers: {
          "user-agent": `octokit-auth-app.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`
        }
      });
      const state = Object.assign(
        {
          request,
          cache: getCache()
        },
        options,
        options.installationId ? { installationId: Number(options.installationId) } : {},
        {
          log,
          oauthApp: (0, import_auth_oauth_app.createOAuthAppAuth)({
            clientType: "github-app",
            clientId: options.clientId || "",
            clientSecret: options.clientSecret || "",
            request
          })
        }
      );
      return Object.assign(auth.bind(null, state), {
        hook: hook.bind(null, state)
      });
    }
  }
});

// node_modules/@octokit/auth-unauthenticated/dist-node/index.js
var require_dist_node21 = __commonJS({
  "node_modules/@octokit/auth-unauthenticated/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      createUnauthenticatedAuth: () => createUnauthenticatedAuth
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    async function auth(reason) {
      return {
        type: "unauthenticated",
        reason
      };
    }
    var import_request_error = require_dist_node4();
    function isRateLimitError(error) {
      if (error.status !== 403) {
        return false;
      }
      if (!error.response) {
        return false;
      }
      return error.response.headers["x-ratelimit-remaining"] === "0";
    }
    var import_request_error2 = require_dist_node4();
    var REGEX_ABUSE_LIMIT_MESSAGE = /\babuse\b/i;
    function isAbuseLimitError(error) {
      if (error.status !== 403) {
        return false;
      }
      return REGEX_ABUSE_LIMIT_MESSAGE.test(error.message);
    }
    async function hook(reason, request, route, parameters) {
      const endpoint = request.endpoint.merge(
        route,
        parameters
      );
      return request(endpoint).catch((error) => {
        if (error.status === 404) {
          error.message = `Not found. May be due to lack of authentication. Reason: ${reason}`;
          throw error;
        }
        if (isRateLimitError(error)) {
          error.message = `API rate limit exceeded. This maybe caused by the lack of authentication. Reason: ${reason}`;
          throw error;
        }
        if (isAbuseLimitError(error)) {
          error.message = `You have triggered an abuse detection mechanism. This maybe caused by the lack of authentication. Reason: ${reason}`;
          throw error;
        }
        if (error.status === 401) {
          error.message = `Unauthorized. "${endpoint.method} ${endpoint.url}" failed most likely due to lack of authentication. Reason: ${reason}`;
          throw error;
        }
        if (error.status >= 400 && error.status < 500) {
          error.message = error.message.replace(
            /\.?$/,
            `. May be caused by lack of authentication (${reason}).`
          );
        }
        throw error;
      });
    }
    var createUnauthenticatedAuth = function createUnauthenticatedAuth2(options) {
      if (!options || !options.reason) {
        throw new Error(
          "[@octokit/auth-unauthenticated] No reason passed to createUnauthenticatedAuth"
        );
      }
      return Object.assign(auth.bind(null, options.reason), {
        hook: hook.bind(null, options.reason)
      });
    };
  }
});

// node_modules/@octokit/oauth-app/dist-node/index.js
var require_dist_node22 = __commonJS({
  "node_modules/@octokit/oauth-app/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __create2 = Object.create;
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __getProtoOf2 = Object.getPrototypeOf;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toESM2 = (mod, isNodeMode, target) => (target = mod != null ? __create2(__getProtoOf2(mod)) : {}, __copyProps2(
      // If the importer is in node compatibility mode or this is not an ESM
      // file that has been converted to a CommonJS file using a Babel-
      // compatible transform (i.e. "__esModule" has not been set), then set
      // "default" to the CommonJS "module.exports" for node compatibility.
      isNodeMode || !mod || !mod.__esModule ? __defProp2(target, "default", { value: mod, enumerable: true }) : target,
      mod
    ));
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      OAuthApp: () => OAuthApp,
      createAWSLambdaAPIGatewayV2Handler: () => createAWSLambdaAPIGatewayV2Handler,
      createNodeMiddleware: () => createNodeMiddleware2,
      createWebWorkerHandler: () => createWebWorkerHandler,
      handleRequest: () => handleRequest,
      sendNodeResponse: () => sendResponse,
      unknownRouteResponse: () => unknownRouteResponse
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_auth_oauth_app = require_dist_node18();
    var VERSION = "6.0.0";
    function addEventHandler(state, eventName, eventHandler) {
      if (Array.isArray(eventName)) {
        for (const singleEventName of eventName) {
          addEventHandler(state, singleEventName, eventHandler);
        }
        return;
      }
      if (!state.eventHandlers[eventName]) {
        state.eventHandlers[eventName] = [];
      }
      state.eventHandlers[eventName].push(eventHandler);
    }
    var import_core = require_dist_node8();
    var import_universal_user_agent = require_dist_node();
    var OAuthAppOctokit = import_core.Octokit.defaults({
      userAgent: `octokit-oauth-app.js/${VERSION} ${(0, import_universal_user_agent.getUserAgent)()}`
    });
    var import_auth_oauth_user = require_dist_node17();
    async function emitEvent(state, context) {
      const { name, action } = context;
      if (state.eventHandlers[`${name}.${action}`]) {
        for (const eventHandler of state.eventHandlers[`${name}.${action}`]) {
          await eventHandler(context);
        }
      }
      if (state.eventHandlers[name]) {
        for (const eventHandler of state.eventHandlers[name]) {
          await eventHandler(context);
        }
      }
    }
    async function getUserOctokitWithState(state, options) {
      return state.octokit.auth({
        type: "oauth-user",
        ...options,
        async factory(options2) {
          const octokit = new state.Octokit({
            authStrategy: import_auth_oauth_user.createOAuthUserAuth,
            auth: options2
          });
          const authentication = await octokit.auth({
            type: "get"
          });
          await emitEvent(state, {
            name: "token",
            action: "created",
            token: authentication.token,
            scopes: authentication.scopes,
            authentication,
            octokit
          });
          return octokit;
        }
      });
    }
    var OAuthMethods = __toESM2(require_dist_node15());
    function getWebFlowAuthorizationUrlWithState(state, options) {
      const optionsWithDefaults = {
        clientId: state.clientId,
        request: state.octokit.request,
        ...options,
        allowSignup: state.allowSignup ?? options.allowSignup,
        redirectUrl: options.redirectUrl ?? state.redirectUrl,
        scopes: options.scopes ?? state.defaultScopes
      };
      return OAuthMethods.getWebFlowAuthorizationUrl({
        clientType: state.clientType,
        ...optionsWithDefaults
      });
    }
    var OAuthAppAuth = __toESM2(require_dist_node18());
    async function createTokenWithState(state, options) {
      const authentication = await state.octokit.auth({
        type: "oauth-user",
        ...options
      });
      await emitEvent(state, {
        name: "token",
        action: "created",
        token: authentication.token,
        scopes: authentication.scopes,
        authentication,
        octokit: new state.Octokit({
          authStrategy: OAuthAppAuth.createOAuthUserAuth,
          auth: {
            clientType: state.clientType,
            clientId: state.clientId,
            clientSecret: state.clientSecret,
            token: authentication.token,
            scopes: authentication.scopes,
            refreshToken: authentication.refreshToken,
            expiresAt: authentication.expiresAt,
            refreshTokenExpiresAt: authentication.refreshTokenExpiresAt
          }
        })
      });
      return { authentication };
    }
    var OAuthMethods2 = __toESM2(require_dist_node15());
    async function checkTokenWithState(state, options) {
      const result = await OAuthMethods2.checkToken({
        // @ts-expect-error not worth the extra code to appease TS
        clientType: state.clientType,
        clientId: state.clientId,
        clientSecret: state.clientSecret,
        request: state.octokit.request,
        ...options
      });
      Object.assign(result.authentication, { type: "token", tokenType: "oauth" });
      return result;
    }
    var OAuthMethods3 = __toESM2(require_dist_node15());
    var import_auth_oauth_user2 = require_dist_node17();
    async function resetTokenWithState(state, options) {
      const optionsWithDefaults = {
        clientId: state.clientId,
        clientSecret: state.clientSecret,
        request: state.octokit.request,
        ...options
      };
      if (state.clientType === "oauth-app") {
        const response2 = await OAuthMethods3.resetToken({
          clientType: "oauth-app",
          ...optionsWithDefaults
        });
        const authentication2 = Object.assign(response2.authentication, {
          type: "token",
          tokenType: "oauth"
        });
        await emitEvent(state, {
          name: "token",
          action: "reset",
          token: response2.authentication.token,
          scopes: response2.authentication.scopes || void 0,
          authentication: authentication2,
          octokit: new state.Octokit({
            authStrategy: import_auth_oauth_user2.createOAuthUserAuth,
            auth: {
              clientType: state.clientType,
              clientId: state.clientId,
              clientSecret: state.clientSecret,
              token: response2.authentication.token,
              scopes: response2.authentication.scopes
            }
          })
        });
        return { ...response2, authentication: authentication2 };
      }
      const response = await OAuthMethods3.resetToken({
        clientType: "github-app",
        ...optionsWithDefaults
      });
      const authentication = Object.assign(response.authentication, {
        type: "token",
        tokenType: "oauth"
      });
      await emitEvent(state, {
        name: "token",
        action: "reset",
        token: response.authentication.token,
        authentication,
        octokit: new state.Octokit({
          authStrategy: import_auth_oauth_user2.createOAuthUserAuth,
          auth: {
            clientType: state.clientType,
            clientId: state.clientId,
            clientSecret: state.clientSecret,
            token: response.authentication.token
          }
        })
      });
      return { ...response, authentication };
    }
    var OAuthMethods4 = __toESM2(require_dist_node15());
    var import_auth_oauth_user3 = require_dist_node17();
    async function refreshTokenWithState(state, options) {
      if (state.clientType === "oauth-app") {
        throw new Error(
          "[@octokit/oauth-app] app.refreshToken() is not supported for OAuth Apps"
        );
      }
      const response = await OAuthMethods4.refreshToken({
        clientType: "github-app",
        clientId: state.clientId,
        clientSecret: state.clientSecret,
        request: state.octokit.request,
        refreshToken: options.refreshToken
      });
      const authentication = Object.assign(response.authentication, {
        type: "token",
        tokenType: "oauth"
      });
      await emitEvent(state, {
        name: "token",
        action: "refreshed",
        token: response.authentication.token,
        authentication,
        octokit: new state.Octokit({
          authStrategy: import_auth_oauth_user3.createOAuthUserAuth,
          auth: {
            clientType: state.clientType,
            clientId: state.clientId,
            clientSecret: state.clientSecret,
            token: response.authentication.token
          }
        })
      });
      return { ...response, authentication };
    }
    var OAuthMethods5 = __toESM2(require_dist_node15());
    var import_auth_oauth_user4 = require_dist_node17();
    async function scopeTokenWithState(state, options) {
      if (state.clientType === "oauth-app") {
        throw new Error(
          "[@octokit/oauth-app] app.scopeToken() is not supported for OAuth Apps"
        );
      }
      const response = await OAuthMethods5.scopeToken({
        clientType: "github-app",
        clientId: state.clientId,
        clientSecret: state.clientSecret,
        request: state.octokit.request,
        ...options
      });
      const authentication = Object.assign(response.authentication, {
        type: "token",
        tokenType: "oauth"
      });
      await emitEvent(state, {
        name: "token",
        action: "scoped",
        token: response.authentication.token,
        authentication,
        octokit: new state.Octokit({
          authStrategy: import_auth_oauth_user4.createOAuthUserAuth,
          auth: {
            clientType: state.clientType,
            clientId: state.clientId,
            clientSecret: state.clientSecret,
            token: response.authentication.token
          }
        })
      });
      return { ...response, authentication };
    }
    var OAuthMethods6 = __toESM2(require_dist_node15());
    var import_auth_unauthenticated = require_dist_node21();
    async function deleteTokenWithState(state, options) {
      const optionsWithDefaults = {
        clientId: state.clientId,
        clientSecret: state.clientSecret,
        request: state.octokit.request,
        ...options
      };
      const response = state.clientType === "oauth-app" ? await OAuthMethods6.deleteToken({
        clientType: "oauth-app",
        ...optionsWithDefaults
      }) : (
        // istanbul ignore next
        await OAuthMethods6.deleteToken({
          clientType: "github-app",
          ...optionsWithDefaults
        })
      );
      await emitEvent(state, {
        name: "token",
        action: "deleted",
        token: options.token,
        octokit: new state.Octokit({
          authStrategy: import_auth_unauthenticated.createUnauthenticatedAuth,
          auth: {
            reason: `Handling "token.deleted" event. The access for the token has been revoked.`
          }
        })
      });
      return response;
    }
    var OAuthMethods7 = __toESM2(require_dist_node15());
    var import_auth_unauthenticated2 = require_dist_node21();
    async function deleteAuthorizationWithState(state, options) {
      const optionsWithDefaults = {
        clientId: state.clientId,
        clientSecret: state.clientSecret,
        request: state.octokit.request,
        ...options
      };
      const response = state.clientType === "oauth-app" ? await OAuthMethods7.deleteAuthorization({
        clientType: "oauth-app",
        ...optionsWithDefaults
      }) : (
        // istanbul ignore next
        await OAuthMethods7.deleteAuthorization({
          clientType: "github-app",
          ...optionsWithDefaults
        })
      );
      await emitEvent(state, {
        name: "token",
        action: "deleted",
        token: options.token,
        octokit: new state.Octokit({
          authStrategy: import_auth_unauthenticated2.createUnauthenticatedAuth,
          auth: {
            reason: `Handling "token.deleted" event. The access for the token has been revoked.`
          }
        })
      });
      await emitEvent(state, {
        name: "authorization",
        action: "deleted",
        token: options.token,
        octokit: new state.Octokit({
          authStrategy: import_auth_unauthenticated2.createUnauthenticatedAuth,
          auth: {
            reason: `Handling "authorization.deleted" event. The access for the app has been revoked.`
          }
        })
      });
      return response;
    }
    function unknownRouteResponse(request) {
      return {
        status: 404,
        headers: { "content-type": "application/json" },
        text: JSON.stringify({
          error: `Unknown route: ${request.method} ${request.url}`
        })
      };
    }
    async function handleRequest(app, { pathPrefix = "/api/github/oauth" }, request) {
      if (request.method === "OPTIONS") {
        return {
          status: 200,
          headers: {
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "*",
            "access-control-allow-headers": "Content-Type, User-Agent, Authorization"
          }
        };
      }
      let { pathname } = new URL(request.url, "http://localhost");
      if (!pathname.startsWith(`${pathPrefix}/`)) {
        return void 0;
      }
      pathname = pathname.slice(pathPrefix.length + 1);
      const route = [request.method, pathname].join(" ");
      const routes = {
        getLogin: `GET login`,
        getCallback: `GET callback`,
        createToken: `POST token`,
        getToken: `GET token`,
        patchToken: `PATCH token`,
        patchRefreshToken: `PATCH refresh-token`,
        scopeToken: `POST token/scoped`,
        deleteToken: `DELETE token`,
        deleteGrant: `DELETE grant`
      };
      if (!Object.values(routes).includes(route)) {
        return unknownRouteResponse(request);
      }
      let json;
      try {
        const text = await request.text();
        json = text ? JSON.parse(text) : {};
      } catch (error) {
        return {
          status: 400,
          headers: {
            "content-type": "application/json",
            "access-control-allow-origin": "*"
          },
          text: JSON.stringify({
            error: "[@octokit/oauth-app] request error"
          })
        };
      }
      const { searchParams } = new URL(request.url, "http://localhost");
      const query = Object.fromEntries(searchParams);
      const headers = request.headers;
      try {
        if (route === routes.getLogin) {
          const { url } = app.getWebFlowAuthorizationUrl({
            state: query.state,
            scopes: query.scopes ? query.scopes.split(",") : void 0,
            allowSignup: query.allowSignup ? query.allowSignup === "true" : void 0,
            redirectUrl: query.redirectUrl
          });
          return { status: 302, headers: { location: url } };
        }
        if (route === routes.getCallback) {
          if (query.error) {
            throw new Error(
              `[@octokit/oauth-app] ${query.error} ${query.error_description}`
            );
          }
          if (!query.code) {
            throw new Error('[@octokit/oauth-app] "code" parameter is required');
          }
          const {
            authentication: { token: token2 }
          } = await app.createToken({
            code: query.code
          });
          return {
            status: 200,
            headers: {
              "content-type": "text/html"
            },
            text: `<h1>Token created successfully</h1>

<p>Your token is: <strong>${token2}</strong>. Copy it now as it cannot be shown again.</p>`
          };
        }
        if (route === routes.createToken) {
          const { code, redirectUrl } = json;
          if (!code) {
            throw new Error('[@octokit/oauth-app] "code" parameter is required');
          }
          const result = await app.createToken({
            code,
            redirectUrl
          });
          delete result.authentication.clientSecret;
          return {
            status: 201,
            headers: {
              "content-type": "application/json",
              "access-control-allow-origin": "*"
            },
            text: JSON.stringify(result)
          };
        }
        if (route === routes.getToken) {
          const token2 = headers.authorization?.substr("token ".length);
          if (!token2) {
            throw new Error(
              '[@octokit/oauth-app] "Authorization" header is required'
            );
          }
          const result = await app.checkToken({
            token: token2
          });
          delete result.authentication.clientSecret;
          return {
            status: 200,
            headers: {
              "content-type": "application/json",
              "access-control-allow-origin": "*"
            },
            text: JSON.stringify(result)
          };
        }
        if (route === routes.patchToken) {
          const token2 = headers.authorization?.substr("token ".length);
          if (!token2) {
            throw new Error(
              '[@octokit/oauth-app] "Authorization" header is required'
            );
          }
          const result = await app.resetToken({ token: token2 });
          delete result.authentication.clientSecret;
          return {
            status: 200,
            headers: {
              "content-type": "application/json",
              "access-control-allow-origin": "*"
            },
            text: JSON.stringify(result)
          };
        }
        if (route === routes.patchRefreshToken) {
          const token2 = headers.authorization?.substr("token ".length);
          if (!token2) {
            throw new Error(
              '[@octokit/oauth-app] "Authorization" header is required'
            );
          }
          const { refreshToken: refreshToken2 } = json;
          if (!refreshToken2) {
            throw new Error(
              "[@octokit/oauth-app] refreshToken must be sent in request body"
            );
          }
          const result = await app.refreshToken({ refreshToken: refreshToken2 });
          delete result.authentication.clientSecret;
          return {
            status: 200,
            headers: {
              "content-type": "application/json",
              "access-control-allow-origin": "*"
            },
            text: JSON.stringify(result)
          };
        }
        if (route === routes.scopeToken) {
          const token2 = headers.authorization?.substr("token ".length);
          if (!token2) {
            throw new Error(
              '[@octokit/oauth-app] "Authorization" header is required'
            );
          }
          const result = await app.scopeToken({
            token: token2,
            ...json
          });
          delete result.authentication.clientSecret;
          return {
            status: 200,
            headers: {
              "content-type": "application/json",
              "access-control-allow-origin": "*"
            },
            text: JSON.stringify(result)
          };
        }
        if (route === routes.deleteToken) {
          const token2 = headers.authorization?.substr("token ".length);
          if (!token2) {
            throw new Error(
              '[@octokit/oauth-app] "Authorization" header is required'
            );
          }
          await app.deleteToken({
            token: token2
          });
          return {
            status: 204,
            headers: { "access-control-allow-origin": "*" }
          };
        }
        const token = headers.authorization?.substr("token ".length);
        if (!token) {
          throw new Error(
            '[@octokit/oauth-app] "Authorization" header is required'
          );
        }
        await app.deleteAuthorization({
          token
        });
        return {
          status: 204,
          headers: { "access-control-allow-origin": "*" }
        };
      } catch (error) {
        return {
          status: 400,
          headers: {
            "content-type": "application/json",
            "access-control-allow-origin": "*"
          },
          text: JSON.stringify({ error: error.message })
        };
      }
    }
    function parseRequest(request) {
      const { method, url, headers } = request;
      async function text() {
        const text2 = await new Promise((resolve, reject) => {
          let bodyChunks = [];
          request.on("error", reject).on("data", (chunk) => bodyChunks.push(chunk)).on("end", () => resolve(Buffer.concat(bodyChunks).toString()));
        });
        return text2;
      }
      return { method, url, headers, text };
    }
    function sendResponse(octokitResponse, response) {
      response.writeHead(octokitResponse.status, octokitResponse.headers);
      response.end(octokitResponse.text);
    }
    function createNodeMiddleware2(app, options = {}) {
      return async function(request, response, next) {
        const octokitRequest = await parseRequest(request);
        const octokitResponse = await handleRequest(app, options, octokitRequest);
        if (octokitResponse) {
          sendResponse(octokitResponse, response);
          return true;
        } else {
          next?.();
          return false;
        }
      };
    }
    function parseRequest2(request) {
      const headers = Object.fromEntries(request.headers.entries());
      return {
        method: request.method,
        url: request.url,
        headers,
        text: () => request.text()
      };
    }
    function sendResponse2(octokitResponse) {
      return new Response(octokitResponse.text, {
        status: octokitResponse.status,
        headers: octokitResponse.headers
      });
    }
    function createWebWorkerHandler(app, options = {}) {
      return async function(request) {
        const octokitRequest = await parseRequest2(request);
        const octokitResponse = await handleRequest(app, options, octokitRequest);
        return octokitResponse ? sendResponse2(octokitResponse) : void 0;
      };
    }
    function parseRequest3(request) {
      const { method } = request.requestContext.http;
      let url = request.rawPath;
      const { stage } = request.requestContext;
      if (url.startsWith("/" + stage))
        url = url.substring(stage.length + 1);
      if (request.rawQueryString)
        url += "?" + request.rawQueryString;
      const headers = request.headers;
      const text = async () => request.body || "";
      return { method, url, headers, text };
    }
    function sendResponse3(octokitResponse) {
      return {
        statusCode: octokitResponse.status,
        headers: octokitResponse.headers,
        body: octokitResponse.text
      };
    }
    function createAWSLambdaAPIGatewayV2Handler(app, options = {}) {
      return async function(event) {
        const request = parseRequest3(event);
        const response = await handleRequest(app, options, request);
        return response ? sendResponse3(response) : void 0;
      };
    }
    var OAuthApp = class {
      static {
        this.VERSION = VERSION;
      }
      static defaults(defaults) {
        const OAuthAppWithDefaults = class extends this {
          constructor(...args) {
            super({
              ...defaults,
              ...args[0]
            });
          }
        };
        return OAuthAppWithDefaults;
      }
      constructor(options) {
        const Octokit2 = options.Octokit || OAuthAppOctokit;
        this.type = options.clientType || "oauth-app";
        const octokit = new Octokit2({
          authStrategy: import_auth_oauth_app.createOAuthAppAuth,
          auth: {
            clientType: this.type,
            clientId: options.clientId,
            clientSecret: options.clientSecret
          }
        });
        const state = {
          clientType: this.type,
          clientId: options.clientId,
          clientSecret: options.clientSecret,
          // @ts-expect-error defaultScopes not permitted for GitHub Apps
          defaultScopes: options.defaultScopes || [],
          allowSignup: options.allowSignup,
          baseUrl: options.baseUrl,
          redirectUrl: options.redirectUrl,
          log: options.log,
          Octokit: Octokit2,
          octokit,
          eventHandlers: {}
        };
        this.on = addEventHandler.bind(null, state);
        this.octokit = octokit;
        this.getUserOctokit = getUserOctokitWithState.bind(null, state);
        this.getWebFlowAuthorizationUrl = getWebFlowAuthorizationUrlWithState.bind(
          null,
          state
        );
        this.createToken = createTokenWithState.bind(
          null,
          state
        );
        this.checkToken = checkTokenWithState.bind(
          null,
          state
        );
        this.resetToken = resetTokenWithState.bind(
          null,
          state
        );
        this.refreshToken = refreshTokenWithState.bind(
          null,
          state
        );
        this.scopeToken = scopeTokenWithState.bind(
          null,
          state
        );
        this.deleteToken = deleteTokenWithState.bind(null, state);
        this.deleteAuthorization = deleteAuthorizationWithState.bind(null, state);
      }
    };
  }
});

// node_modules/indent-string/index.js
var require_indent_string = __commonJS({
  "node_modules/indent-string/index.js"(exports2, module2) {
    "use strict";
    module2.exports = (string, count = 1, options) => {
      options = {
        indent: " ",
        includeEmptyLines: false,
        ...options
      };
      if (typeof string !== "string") {
        throw new TypeError(
          `Expected \`input\` to be a \`string\`, got \`${typeof string}\``
        );
      }
      if (typeof count !== "number") {
        throw new TypeError(
          `Expected \`count\` to be a \`number\`, got \`${typeof count}\``
        );
      }
      if (typeof options.indent !== "string") {
        throw new TypeError(
          `Expected \`options.indent\` to be a \`string\`, got \`${typeof options.indent}\``
        );
      }
      if (count === 0) {
        return string;
      }
      const regex = options.includeEmptyLines ? /^/gm : /^(?!\s*$)/gm;
      return string.replace(regex, options.indent.repeat(count));
    };
  }
});

// node_modules/clean-stack/index.js
var require_clean_stack = __commonJS({
  "node_modules/clean-stack/index.js"(exports2, module2) {
    "use strict";
    var os = require("os");
    var extractPathRegex = /\s+at.*(?:\(|\s)(.*)\)?/;
    var pathRegex = /^(?:(?:(?:node|(?:internal\/[\w/]*|.*node_modules\/(?:babel-polyfill|pirates)\/.*)?\w+)\.js:\d+:\d+)|native)/;
    var homeDir = typeof os.homedir === "undefined" ? "" : os.homedir();
    module2.exports = (stack, options) => {
      options = Object.assign({ pretty: false }, options);
      return stack.replace(/\\/g, "/").split("\n").filter((line) => {
        const pathMatches = line.match(extractPathRegex);
        if (pathMatches === null || !pathMatches[1]) {
          return true;
        }
        const match = pathMatches[1];
        if (match.includes(".app/Contents/Resources/electron.asar") || match.includes(".app/Contents/Resources/default_app.asar")) {
          return false;
        }
        return !pathRegex.test(match);
      }).filter((line) => line.trim() !== "").map((line) => {
        if (options.pretty) {
          return line.replace(extractPathRegex, (m, p1) => m.replace(p1, p1.replace(homeDir, "~")));
        }
        return line;
      }).join("\n");
    };
  }
});

// node_modules/aggregate-error/index.js
var require_aggregate_error = __commonJS({
  "node_modules/aggregate-error/index.js"(exports2, module2) {
    "use strict";
    var indentString = require_indent_string();
    var cleanStack = require_clean_stack();
    var cleanInternalStack = (stack) => stack.replace(/\s+at .*aggregate-error\/index.js:\d+:\d+\)?/g, "");
    var AggregateError = class extends Error {
      constructor(errors) {
        if (!Array.isArray(errors)) {
          throw new TypeError(`Expected input to be an Array, got ${typeof errors}`);
        }
        errors = [...errors].map((error) => {
          if (error instanceof Error) {
            return error;
          }
          if (error !== null && typeof error === "object") {
            return Object.assign(new Error(error.message), error);
          }
          return new Error(error);
        });
        let message = errors.map((error) => {
          return typeof error.stack === "string" ? cleanInternalStack(cleanStack(error.stack)) : String(error);
        }).join("\n");
        message = "\n" + indentString(message, 4);
        super(message);
        this.name = "AggregateError";
        Object.defineProperty(this, "_errors", { value: errors });
      }
      *[Symbol.iterator]() {
        for (const error of this._errors) {
          yield error;
        }
      }
    };
    module2.exports = AggregateError;
  }
});

// node_modules/@octokit/webhooks-methods/dist-node/index.js
var require_dist_node23 = __commonJS({
  "node_modules/@octokit/webhooks-methods/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      sign: () => sign,
      verify: () => verify,
      verifyWithFallback: () => verifyWithFallback
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_crypto4 = require("crypto");
    var Algorithm = /* @__PURE__ */ ((Algorithm2) => {
      Algorithm2["SHA1"] = "sha1";
      Algorithm2["SHA256"] = "sha256";
      return Algorithm2;
    })(Algorithm || {});
    var VERSION = "4.0.0";
    async function sign(options, payload) {
      const { secret, algorithm } = typeof options === "object" ? {
        secret: options.secret,
        algorithm: options.algorithm || Algorithm.SHA256
      } : { secret: options, algorithm: Algorithm.SHA256 };
      if (!secret || !payload) {
        throw new TypeError(
          "[@octokit/webhooks-methods] secret & payload required for sign()"
        );
      }
      if (!Object.values(Algorithm).includes(algorithm)) {
        throw new TypeError(
          `[@octokit/webhooks] Algorithm ${algorithm} is not supported. Must be  'sha1' or 'sha256'`
        );
      }
      return `${algorithm}=${(0, import_crypto4.createHmac)(algorithm, secret).update(payload).digest("hex")}`;
    }
    sign.VERSION = VERSION;
    var import_crypto22 = require("crypto");
    var import_buffer = require("buffer");
    var getAlgorithm = (signature) => {
      return signature.startsWith("sha256=") ? "sha256" : "sha1";
    };
    async function verify(secret, eventPayload, signature) {
      if (!secret || !eventPayload || !signature) {
        throw new TypeError(
          "[@octokit/webhooks-methods] secret, eventPayload & signature required"
        );
      }
      const signatureBuffer = import_buffer.Buffer.from(signature);
      const algorithm = getAlgorithm(signature);
      const verificationBuffer = import_buffer.Buffer.from(
        await sign({ secret, algorithm }, eventPayload)
      );
      if (signatureBuffer.length !== verificationBuffer.length) {
        return false;
      }
      return (0, import_crypto22.timingSafeEqual)(signatureBuffer, verificationBuffer);
    }
    verify.VERSION = VERSION;
    async function verifyWithFallback(secret, payload, signature, additionalSecrets) {
      const firstPass = await verify(secret, payload, signature);
      if (firstPass) {
        return true;
      }
      if (additionalSecrets !== void 0) {
        for (const s of additionalSecrets) {
          const v = await verify(s, payload, signature);
          if (v) {
            return v;
          }
        }
      }
      return false;
    }
  }
});

// node_modules/@octokit/webhooks/dist-node/index.js
var require_dist_node24 = __commonJS({
  "node_modules/@octokit/webhooks/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __create2 = Object.create;
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __getProtoOf2 = Object.getPrototypeOf;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toESM2 = (mod, isNodeMode, target) => (target = mod != null ? __create2(__getProtoOf2(mod)) : {}, __copyProps2(
      // If the importer is in node compatibility mode or this is not an ESM
      // file that has been converted to a CommonJS file using a Babel-
      // compatible transform (i.e. "__esModule" has not been set), then set
      // "default" to the CommonJS "module.exports" for node compatibility.
      isNodeMode || !mod || !mod.__esModule ? __defProp2(target, "default", { value: mod, enumerable: true }) : target,
      mod
    ));
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      Webhooks: () => Webhooks,
      createEventHandler: () => createEventHandler,
      createNodeMiddleware: () => createNodeMiddleware2,
      emitterEventNames: () => emitterEventNames
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var createLogger = (logger) => ({
      debug: () => {
      },
      info: () => {
      },
      warn: console.warn.bind(console),
      error: console.error.bind(console),
      ...logger
    });
    var emitterEventNames = [
      "branch_protection_rule",
      "branch_protection_rule.created",
      "branch_protection_rule.deleted",
      "branch_protection_rule.edited",
      "check_run",
      "check_run.completed",
      "check_run.created",
      "check_run.requested_action",
      "check_run.rerequested",
      "check_suite",
      "check_suite.completed",
      "check_suite.requested",
      "check_suite.rerequested",
      "code_scanning_alert",
      "code_scanning_alert.appeared_in_branch",
      "code_scanning_alert.closed_by_user",
      "code_scanning_alert.created",
      "code_scanning_alert.fixed",
      "code_scanning_alert.reopened",
      "code_scanning_alert.reopened_by_user",
      "commit_comment",
      "commit_comment.created",
      "create",
      "delete",
      "dependabot_alert",
      "dependabot_alert.created",
      "dependabot_alert.dismissed",
      "dependabot_alert.fixed",
      "dependabot_alert.reintroduced",
      "dependabot_alert.reopened",
      "deploy_key",
      "deploy_key.created",
      "deploy_key.deleted",
      "deployment",
      "deployment.created",
      "deployment_protection_rule",
      "deployment_protection_rule.requested",
      "deployment_status",
      "deployment_status.created",
      "discussion",
      "discussion.answered",
      "discussion.category_changed",
      "discussion.created",
      "discussion.deleted",
      "discussion.edited",
      "discussion.labeled",
      "discussion.locked",
      "discussion.pinned",
      "discussion.transferred",
      "discussion.unanswered",
      "discussion.unlabeled",
      "discussion.unlocked",
      "discussion.unpinned",
      "discussion_comment",
      "discussion_comment.created",
      "discussion_comment.deleted",
      "discussion_comment.edited",
      "fork",
      "github_app_authorization",
      "github_app_authorization.revoked",
      "gollum",
      "installation",
      "installation.created",
      "installation.deleted",
      "installation.new_permissions_accepted",
      "installation.suspend",
      "installation.unsuspend",
      "installation_repositories",
      "installation_repositories.added",
      "installation_repositories.removed",
      "installation_target",
      "installation_target.renamed",
      "issue_comment",
      "issue_comment.created",
      "issue_comment.deleted",
      "issue_comment.edited",
      "issues",
      "issues.assigned",
      "issues.closed",
      "issues.deleted",
      "issues.demilestoned",
      "issues.edited",
      "issues.labeled",
      "issues.locked",
      "issues.milestoned",
      "issues.opened",
      "issues.pinned",
      "issues.reopened",
      "issues.transferred",
      "issues.unassigned",
      "issues.unlabeled",
      "issues.unlocked",
      "issues.unpinned",
      "label",
      "label.created",
      "label.deleted",
      "label.edited",
      "marketplace_purchase",
      "marketplace_purchase.cancelled",
      "marketplace_purchase.changed",
      "marketplace_purchase.pending_change",
      "marketplace_purchase.pending_change_cancelled",
      "marketplace_purchase.purchased",
      "member",
      "member.added",
      "member.edited",
      "member.removed",
      "membership",
      "membership.added",
      "membership.removed",
      "merge_group",
      "merge_group.checks_requested",
      "meta",
      "meta.deleted",
      "milestone",
      "milestone.closed",
      "milestone.created",
      "milestone.deleted",
      "milestone.edited",
      "milestone.opened",
      "org_block",
      "org_block.blocked",
      "org_block.unblocked",
      "organization",
      "organization.deleted",
      "organization.member_added",
      "organization.member_invited",
      "organization.member_removed",
      "organization.renamed",
      "package",
      "package.published",
      "package.updated",
      "page_build",
      "ping",
      "project",
      "project.closed",
      "project.created",
      "project.deleted",
      "project.edited",
      "project.reopened",
      "project_card",
      "project_card.converted",
      "project_card.created",
      "project_card.deleted",
      "project_card.edited",
      "project_card.moved",
      "project_column",
      "project_column.created",
      "project_column.deleted",
      "project_column.edited",
      "project_column.moved",
      "projects_v2_item",
      "projects_v2_item.archived",
      "projects_v2_item.converted",
      "projects_v2_item.created",
      "projects_v2_item.deleted",
      "projects_v2_item.edited",
      "projects_v2_item.reordered",
      "projects_v2_item.restored",
      "public",
      "pull_request",
      "pull_request.assigned",
      "pull_request.auto_merge_disabled",
      "pull_request.auto_merge_enabled",
      "pull_request.closed",
      "pull_request.converted_to_draft",
      "pull_request.demilestoned",
      "pull_request.dequeued",
      "pull_request.edited",
      "pull_request.enqueued",
      "pull_request.labeled",
      "pull_request.locked",
      "pull_request.milestoned",
      "pull_request.opened",
      "pull_request.ready_for_review",
      "pull_request.reopened",
      "pull_request.review_request_removed",
      "pull_request.review_requested",
      "pull_request.synchronize",
      "pull_request.unassigned",
      "pull_request.unlabeled",
      "pull_request.unlocked",
      "pull_request_review",
      "pull_request_review.dismissed",
      "pull_request_review.edited",
      "pull_request_review.submitted",
      "pull_request_review_comment",
      "pull_request_review_comment.created",
      "pull_request_review_comment.deleted",
      "pull_request_review_comment.edited",
      "pull_request_review_thread",
      "pull_request_review_thread.resolved",
      "pull_request_review_thread.unresolved",
      "push",
      "registry_package",
      "registry_package.published",
      "registry_package.updated",
      "release",
      "release.created",
      "release.deleted",
      "release.edited",
      "release.prereleased",
      "release.published",
      "release.released",
      "release.unpublished",
      "repository",
      "repository.archived",
      "repository.created",
      "repository.deleted",
      "repository.edited",
      "repository.privatized",
      "repository.publicized",
      "repository.renamed",
      "repository.transferred",
      "repository.unarchived",
      "repository_dispatch",
      "repository_import",
      "repository_vulnerability_alert",
      "repository_vulnerability_alert.create",
      "repository_vulnerability_alert.dismiss",
      "repository_vulnerability_alert.reopen",
      "repository_vulnerability_alert.resolve",
      "secret_scanning_alert",
      "secret_scanning_alert.created",
      "secret_scanning_alert.reopened",
      "secret_scanning_alert.resolved",
      "secret_scanning_alert.revoked",
      "secret_scanning_alert_location",
      "secret_scanning_alert_location.created",
      "security_advisory",
      "security_advisory.performed",
      "security_advisory.published",
      "security_advisory.updated",
      "security_advisory.withdrawn",
      "sponsorship",
      "sponsorship.cancelled",
      "sponsorship.created",
      "sponsorship.edited",
      "sponsorship.pending_cancellation",
      "sponsorship.pending_tier_change",
      "sponsorship.tier_changed",
      "star",
      "star.created",
      "star.deleted",
      "status",
      "team",
      "team.added_to_repository",
      "team.created",
      "team.deleted",
      "team.edited",
      "team.removed_from_repository",
      "team_add",
      "watch",
      "watch.started",
      "workflow_dispatch",
      "workflow_job",
      "workflow_job.completed",
      "workflow_job.in_progress",
      "workflow_job.queued",
      "workflow_job.waiting",
      "workflow_run",
      "workflow_run.completed",
      "workflow_run.in_progress",
      "workflow_run.requested"
    ];
    function handleEventHandlers(state, webhookName, handler) {
      if (!state.hooks[webhookName]) {
        state.hooks[webhookName] = [];
      }
      state.hooks[webhookName].push(handler);
    }
    function receiverOn(state, webhookNameOrNames, handler) {
      if (Array.isArray(webhookNameOrNames)) {
        webhookNameOrNames.forEach(
          (webhookName) => receiverOn(state, webhookName, handler)
        );
        return;
      }
      if (["*", "error"].includes(webhookNameOrNames)) {
        const webhookName = webhookNameOrNames === "*" ? "any" : webhookNameOrNames;
        const message = `Using the "${webhookNameOrNames}" event with the regular Webhooks.on() function is not supported. Please use the Webhooks.on${webhookName.charAt(0).toUpperCase() + webhookName.slice(1)}() method instead`;
        throw new Error(message);
      }
      if (!emitterEventNames.includes(webhookNameOrNames)) {
        state.log.warn(
          `"${webhookNameOrNames}" is not a known webhook name (https://developer.github.com/v3/activity/events/types/)`
        );
      }
      handleEventHandlers(state, webhookNameOrNames, handler);
    }
    function receiverOnAny(state, handler) {
      handleEventHandlers(state, "*", handler);
    }
    function receiverOnError(state, handler) {
      handleEventHandlers(state, "error", handler);
    }
    var import_aggregate_error = __toESM2(require_aggregate_error());
    function wrapErrorHandler(handler, error) {
      let returnValue;
      try {
        returnValue = handler(error);
      } catch (error2) {
        console.log('FATAL: Error occurred in "error" event handler');
        console.log(error2);
      }
      if (returnValue && returnValue.catch) {
        returnValue.catch((error2) => {
          console.log('FATAL: Error occurred in "error" event handler');
          console.log(error2);
        });
      }
    }
    function getHooks(state, eventPayloadAction, eventName) {
      const hooks = [state.hooks[eventName], state.hooks["*"]];
      if (eventPayloadAction) {
        hooks.unshift(state.hooks[`${eventName}.${eventPayloadAction}`]);
      }
      return [].concat(...hooks.filter(Boolean));
    }
    function receiverHandle(state, event) {
      const errorHandlers = state.hooks.error || [];
      if (event instanceof Error) {
        const error = Object.assign(new import_aggregate_error.default([event]), {
          event,
          errors: [event]
        });
        errorHandlers.forEach((handler) => wrapErrorHandler(handler, error));
        return Promise.reject(error);
      }
      if (!event || !event.name) {
        throw new import_aggregate_error.default(["Event name not passed"]);
      }
      if (!event.payload) {
        throw new import_aggregate_error.default(["Event payload not passed"]);
      }
      const hooks = getHooks(
        state,
        "action" in event.payload ? event.payload.action : null,
        event.name
      );
      if (hooks.length === 0) {
        return Promise.resolve();
      }
      const errors = [];
      const promises = hooks.map((handler) => {
        let promise = Promise.resolve(event);
        if (state.transform) {
          promise = promise.then(state.transform);
        }
        return promise.then((event2) => {
          return handler(event2);
        }).catch((error) => errors.push(Object.assign(error, { event })));
      });
      return Promise.all(promises).then(() => {
        if (errors.length === 0) {
          return;
        }
        const error = new import_aggregate_error.default(errors);
        Object.assign(error, {
          event,
          errors
        });
        errorHandlers.forEach((handler) => wrapErrorHandler(handler, error));
        throw error;
      });
    }
    function removeListener(state, webhookNameOrNames, handler) {
      if (Array.isArray(webhookNameOrNames)) {
        webhookNameOrNames.forEach(
          (webhookName) => removeListener(state, webhookName, handler)
        );
        return;
      }
      if (!state.hooks[webhookNameOrNames]) {
        return;
      }
      for (let i = state.hooks[webhookNameOrNames].length - 1; i >= 0; i--) {
        if (state.hooks[webhookNameOrNames][i] === handler) {
          state.hooks[webhookNameOrNames].splice(i, 1);
          return;
        }
      }
    }
    function createEventHandler(options) {
      const state = {
        hooks: {},
        log: createLogger(options && options.log)
      };
      if (options && options.transform) {
        state.transform = options.transform;
      }
      return {
        on: receiverOn.bind(null, state),
        onAny: receiverOnAny.bind(null, state),
        onError: receiverOnError.bind(null, state),
        removeListener: removeListener.bind(null, state),
        receive: receiverHandle.bind(null, state)
      };
    }
    var import_webhooks_methods2 = require_dist_node23();
    var import_aggregate_error2 = __toESM2(require_aggregate_error());
    var import_webhooks_methods = require_dist_node23();
    async function verifyAndReceive(state, event) {
      const matchesSignature = await (0, import_webhooks_methods.verify)(
        state.secret,
        event.payload,
        event.signature
      ).catch(() => false);
      if (!matchesSignature) {
        const error = new Error(
          "[@octokit/webhooks] signature does not match event payload and secret"
        );
        return state.eventHandler.receive(
          Object.assign(error, { event, status: 400 })
        );
      }
      let payload;
      try {
        payload = JSON.parse(event.payload);
      } catch (error) {
        error.message = "Invalid JSON";
        error.status = 400;
        throw new import_aggregate_error2.default([error]);
      }
      return state.eventHandler.receive({
        id: event.id,
        name: event.name,
        payload
      });
    }
    var WEBHOOK_HEADERS = [
      "x-github-event",
      "x-hub-signature-256",
      "x-github-delivery"
    ];
    function getMissingHeaders(request) {
      return WEBHOOK_HEADERS.filter((header) => !(header in request.headers));
    }
    var import_aggregate_error3 = __toESM2(require_aggregate_error());
    function getPayload(request) {
      if (request.body)
        return Promise.resolve(request.body);
      return new Promise((resolve, reject) => {
        let data = "";
        request.setEncoding("utf8");
        request.on("error", (error) => reject(new import_aggregate_error3.default([error])));
        request.on("data", (chunk) => data += chunk);
        request.on("end", () => resolve(data));
      });
    }
    function onUnhandledRequestDefault(request, response) {
      response.writeHead(404, {
        "content-type": "application/json"
      });
      response.end(
        JSON.stringify({
          error: `Unknown route: ${request.method} ${request.url}`
        })
      );
    }
    async function middleware(webhooks, options, request, response, next) {
      let pathname;
      try {
        pathname = new URL(request.url, "http://localhost").pathname;
      } catch (error) {
        response.writeHead(422, {
          "content-type": "application/json"
        });
        response.end(
          JSON.stringify({
            error: `Request URL could not be parsed: ${request.url}`
          })
        );
        return true;
      }
      if (pathname !== options.path) {
        next?.();
        return false;
      } else if (request.method !== "POST") {
        onUnhandledRequestDefault(request, response);
        return true;
      }
      if (!request.headers["content-type"] || !request.headers["content-type"].startsWith("application/json")) {
        response.writeHead(415, {
          "content-type": "application/json",
          accept: "application/json"
        });
        response.end(
          JSON.stringify({
            error: `Unsupported "Content-Type" header value. Must be "application/json"`
          })
        );
        return true;
      }
      const missingHeaders = getMissingHeaders(request).join(", ");
      if (missingHeaders) {
        response.writeHead(400, {
          "content-type": "application/json"
        });
        response.end(
          JSON.stringify({
            error: `Required headers missing: ${missingHeaders}`
          })
        );
        return true;
      }
      const eventName = request.headers["x-github-event"];
      const signatureSHA256 = request.headers["x-hub-signature-256"];
      const id = request.headers["x-github-delivery"];
      options.log.debug(`${eventName} event received (id: ${id})`);
      let didTimeout = false;
      const timeout = setTimeout(() => {
        didTimeout = true;
        response.statusCode = 202;
        response.end("still processing\n");
      }, 9e3).unref();
      try {
        const payload = await getPayload(request);
        await webhooks.verifyAndReceive({
          id,
          name: eventName,
          payload,
          signature: signatureSHA256
        });
        clearTimeout(timeout);
        if (didTimeout)
          return true;
        response.end("ok\n");
        return true;
      } catch (error) {
        clearTimeout(timeout);
        if (didTimeout)
          return true;
        const err = Array.from(error)[0];
        const errorMessage = err.message ? `${err.name}: ${err.message}` : "Error: An Unspecified error occurred";
        response.statusCode = typeof err.status !== "undefined" ? err.status : 500;
        options.log.error(error);
        response.end(
          JSON.stringify({
            error: errorMessage
          })
        );
        return true;
      }
    }
    function createNodeMiddleware2(webhooks, {
      path: path2 = "/api/github/webhooks",
      log = createLogger()
    } = {}) {
      return middleware.bind(null, webhooks, {
        path: path2,
        log
      });
    }
    var Webhooks = class {
      constructor(options) {
        if (!options || !options.secret) {
          throw new Error("[@octokit/webhooks] options.secret required");
        }
        const state = {
          eventHandler: createEventHandler(options),
          secret: options.secret,
          hooks: {},
          log: createLogger(options.log)
        };
        this.sign = import_webhooks_methods2.sign.bind(null, options.secret);
        this.verify = import_webhooks_methods2.verify.bind(null, options.secret);
        this.on = state.eventHandler.on;
        this.onAny = state.eventHandler.onAny;
        this.onError = state.eventHandler.onError;
        this.removeListener = state.eventHandler.removeListener;
        this.receive = state.eventHandler.receive;
        this.verifyAndReceive = verifyAndReceive.bind(null, state);
      }
    };
  }
});

// node_modules/@octokit/app/dist-node/index.js
var require_dist_node25 = __commonJS({
  "node_modules/@octokit/app/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      App: () => App,
      createNodeMiddleware: () => createNodeMiddleware2
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_core5 = require_dist_node8();
    var import_auth_app3 = require_dist_node20();
    var import_oauth_app2 = require_dist_node22();
    var import_webhooks3 = require_dist_node24();
    var VERSION = "14.0.2";
    var import_core = require_dist_node8();
    var import_auth_app = require_dist_node20();
    var import_auth_unauthenticated = require_dist_node21();
    var import_webhooks = require_dist_node24();
    function webhooks(appOctokit, options) {
      return new import_webhooks.Webhooks({
        secret: options.secret,
        transform: async (event) => {
          if (!("installation" in event.payload) || typeof event.payload.installation !== "object") {
            const octokit2 = new appOctokit.constructor({
              authStrategy: import_auth_unauthenticated.createUnauthenticatedAuth,
              auth: {
                reason: `"installation" key missing in webhook event payload`
              }
            });
            return {
              ...event,
              octokit: octokit2
            };
          }
          const installationId = event.payload.installation.id;
          const octokit = await appOctokit.auth({
            type: "installation",
            installationId,
            factory(auth) {
              return new auth.octokit.constructor({
                ...auth.octokitOptions,
                authStrategy: import_auth_app.createAppAuth,
                ...{
                  auth: {
                    ...auth,
                    installationId
                  }
                }
              });
            }
          });
          octokit.hook.before("request", (options2) => {
            options2.headers["x-github-delivery"] = event.id;
          });
          return {
            ...event,
            octokit
          };
        }
      });
    }
    var import_plugin_paginate_rest = require_dist_node9();
    var import_core3 = require_dist_node8();
    var import_auth_app2 = require_dist_node20();
    var import_core2 = require_dist_node8();
    async function getInstallationOctokit(app, installationId) {
      return app.octokit.auth({
        type: "installation",
        installationId,
        factory(auth) {
          const options = {
            ...auth.octokitOptions,
            authStrategy: import_auth_app2.createAppAuth,
            ...{ auth: { ...auth, installationId } }
          };
          return new auth.octokit.constructor(options);
        }
      });
    }
    function eachInstallationFactory(app) {
      return Object.assign(eachInstallation.bind(null, app), {
        iterator: eachInstallationIterator.bind(null, app)
      });
    }
    async function eachInstallation(app, callback) {
      const i = eachInstallationIterator(app)[Symbol.asyncIterator]();
      let result = await i.next();
      while (!result.done) {
        await callback(result.value);
        result = await i.next();
      }
    }
    function eachInstallationIterator(app) {
      return {
        async *[Symbol.asyncIterator]() {
          const iterator = import_plugin_paginate_rest.composePaginateRest.iterator(
            app.octokit,
            "GET /app/installations"
          );
          for await (const { data: installations } of iterator) {
            for (const installation of installations) {
              const installationOctokit = await getInstallationOctokit(
                app,
                installation.id
              );
              yield { octokit: installationOctokit, installation };
            }
          }
        }
      };
    }
    var import_plugin_paginate_rest2 = require_dist_node9();
    var import_core4 = require_dist_node8();
    function eachRepositoryFactory(app) {
      return Object.assign(eachRepository.bind(null, app), {
        iterator: eachRepositoryIterator.bind(null, app)
      });
    }
    async function eachRepository(app, queryOrCallback, callback) {
      const i = eachRepositoryIterator(
        app,
        callback ? queryOrCallback : void 0
      )[Symbol.asyncIterator]();
      let result = await i.next();
      while (!result.done) {
        if (callback) {
          await callback(result.value);
        } else {
          await queryOrCallback(result.value);
        }
        result = await i.next();
      }
    }
    function singleInstallationIterator(app, installationId) {
      return {
        async *[Symbol.asyncIterator]() {
          yield {
            octokit: await app.getInstallationOctokit(installationId)
          };
        }
      };
    }
    function eachRepositoryIterator(app, query) {
      return {
        async *[Symbol.asyncIterator]() {
          const iterator = query ? singleInstallationIterator(app, query.installationId) : app.eachInstallation.iterator();
          for await (const { octokit } of iterator) {
            const repositoriesIterator = import_plugin_paginate_rest2.composePaginateRest.iterator(
              octokit,
              "GET /installation/repositories"
            );
            for await (const { data: repositories } of repositoriesIterator) {
              for (const repository of repositories) {
                yield { octokit, repository };
              }
            }
          }
        }
      };
    }
    var import_oauth_app = require_dist_node22();
    var import_webhooks2 = require_dist_node24();
    function noop() {
    }
    function createNodeMiddleware2(app, options = {}) {
      const log = Object.assign(
        {
          debug: noop,
          info: noop,
          warn: console.warn.bind(console),
          error: console.error.bind(console)
        },
        options.log
      );
      const optionsWithDefaults = {
        pathPrefix: "/api/github",
        ...options,
        log
      };
      const webhooksMiddleware = (0, import_webhooks2.createNodeMiddleware)(app.webhooks, {
        path: optionsWithDefaults.pathPrefix + "/webhooks",
        log
      });
      const oauthMiddleware = (0, import_oauth_app.createNodeMiddleware)(app.oauth, {
        pathPrefix: optionsWithDefaults.pathPrefix + "/oauth"
      });
      return middleware.bind(
        null,
        optionsWithDefaults.pathPrefix,
        webhooksMiddleware,
        oauthMiddleware
      );
    }
    async function middleware(pathPrefix, webhooksMiddleware, oauthMiddleware, request, response, next) {
      const { pathname } = new URL(request.url, "http://localhost");
      if (pathname.startsWith(`${pathPrefix}/`)) {
        if (pathname === `${pathPrefix}/webhooks`) {
          webhooksMiddleware(request, response);
        } else if (pathname.startsWith(`${pathPrefix}/oauth/`)) {
          oauthMiddleware(request, response);
        } else {
          (0, import_oauth_app.sendNodeResponse)((0, import_oauth_app.unknownRouteResponse)(request), response);
        }
        return true;
      } else {
        next == null ? void 0 : next();
        return false;
      }
    }
    var _App = class _App {
      static defaults(defaults) {
        const AppWithDefaults = class extends this {
          constructor(...args) {
            super({
              ...defaults,
              ...args[0]
            });
          }
        };
        return AppWithDefaults;
      }
      constructor(options) {
        const Octokit5 = options.Octokit || import_core5.Octokit;
        const authOptions = Object.assign(
          {
            appId: options.appId,
            privateKey: options.privateKey
          },
          options.oauth ? {
            clientId: options.oauth.clientId,
            clientSecret: options.oauth.clientSecret
          } : {}
        );
        this.octokit = new Octokit5({
          authStrategy: import_auth_app3.createAppAuth,
          auth: authOptions,
          log: options.log
        });
        this.log = Object.assign(
          {
            debug: () => {
            },
            info: () => {
            },
            warn: console.warn.bind(console),
            error: console.error.bind(console)
          },
          options.log
        );
        if (options.webhooks) {
          this.webhooks = webhooks(this.octokit, options.webhooks);
        } else {
          Object.defineProperty(this, "webhooks", {
            get() {
              throw new Error("[@octokit/app] webhooks option not set");
            }
          });
        }
        if (options.oauth) {
          this.oauth = new import_oauth_app2.OAuthApp({
            ...options.oauth,
            clientType: "github-app",
            Octokit: Octokit5
          });
        } else {
          Object.defineProperty(this, "oauth", {
            get() {
              throw new Error(
                "[@octokit/app] oauth.clientId / oauth.clientSecret options are not set"
              );
            }
          });
        }
        this.getInstallationOctokit = getInstallationOctokit.bind(
          null,
          this
        );
        this.eachInstallation = eachInstallationFactory(
          this
        );
        this.eachRepository = eachRepositoryFactory(
          this
        );
      }
    };
    _App.VERSION = VERSION;
    var App = _App;
  }
});

// node_modules/octokit/dist-node/index.js
var require_dist_node26 = __commonJS({
  "node_modules/octokit/dist-node/index.js"(exports2, module2) {
    "use strict";
    var __defProp2 = Object.defineProperty;
    var __getOwnPropDesc2 = Object.getOwnPropertyDescriptor;
    var __getOwnPropNames2 = Object.getOwnPropertyNames;
    var __hasOwnProp2 = Object.prototype.hasOwnProperty;
    var __export2 = (target, all) => {
      for (var name in all)
        __defProp2(target, name, { get: all[name], enumerable: true });
    };
    var __copyProps2 = (to, from, except, desc) => {
      if (from && typeof from === "object" || typeof from === "function") {
        for (let key of __getOwnPropNames2(from))
          if (!__hasOwnProp2.call(to, key) && key !== except)
            __defProp2(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc2(from, key)) || desc.enumerable });
      }
      return to;
    };
    var __toCommonJS2 = (mod) => __copyProps2(__defProp2({}, "__esModule", { value: true }), mod);
    var dist_src_exports = {};
    __export2(dist_src_exports, {
      App: () => App,
      OAuthApp: () => OAuthApp,
      Octokit: () => Octokit2,
      RequestError: () => import_request_error.RequestError,
      createNodeMiddleware: () => import_app2.createNodeMiddleware
    });
    module2.exports = __toCommonJS2(dist_src_exports);
    var import_core = require_dist_node8();
    var import_plugin_paginate_rest = require_dist_node9();
    var import_plugin_paginate_graphql = require_dist_node10();
    var import_plugin_rest_endpoint_methods = require_dist_node11();
    var import_plugin_retry = require_dist_node12();
    var import_plugin_throttling = require_dist_node13();
    var VERSION = "3.1.2";
    var import_request_error = require_dist_node4();
    var Octokit2 = import_core.Octokit.plugin(
      import_plugin_rest_endpoint_methods.restEndpointMethods,
      import_plugin_paginate_rest.paginateRest,
      import_plugin_paginate_graphql.paginateGraphql,
      import_plugin_retry.retry,
      import_plugin_throttling.throttling
    ).defaults({
      userAgent: `octokit.js/${VERSION}`,
      throttle: {
        onRateLimit,
        onSecondaryRateLimit
      }
    });
    function onRateLimit(retryAfter, options, octokit) {
      octokit.log.warn(
        `Request quota exhausted for request ${options.method} ${options.url}`
      );
      if (options.request.retryCount === 0) {
        octokit.log.info(`Retrying after ${retryAfter} seconds!`);
        return true;
      }
    }
    function onSecondaryRateLimit(retryAfter, options, octokit) {
      octokit.log.warn(
        `SecondaryRateLimit detected for request ${options.method} ${options.url}`
      );
      if (options.request.retryCount === 0) {
        octokit.log.info(`Retrying after ${retryAfter} seconds!`);
        return true;
      }
    }
    var import_app = require_dist_node25();
    var import_oauth_app = require_dist_node22();
    var import_app2 = require_dist_node25();
    var App = import_app.App.defaults({ Octokit: Octokit2 });
    var OAuthApp = import_oauth_app.OAuthApp.defaults({ Octokit: Octokit2 });
  }
});

// node_modules/dotenv/package.json
var require_package = __commonJS({
  "node_modules/dotenv/package.json"(exports2, module2) {
    module2.exports = {
      name: "dotenv",
      version: "16.3.1",
      description: "Loads environment variables from .env file",
      main: "lib/main.js",
      types: "lib/main.d.ts",
      exports: {
        ".": {
          types: "./lib/main.d.ts",
          require: "./lib/main.js",
          default: "./lib/main.js"
        },
        "./config": "./config.js",
        "./config.js": "./config.js",
        "./lib/env-options": "./lib/env-options.js",
        "./lib/env-options.js": "./lib/env-options.js",
        "./lib/cli-options": "./lib/cli-options.js",
        "./lib/cli-options.js": "./lib/cli-options.js",
        "./package.json": "./package.json"
      },
      scripts: {
        "dts-check": "tsc --project tests/types/tsconfig.json",
        lint: "standard",
        "lint-readme": "standard-markdown",
        pretest: "npm run lint && npm run dts-check",
        test: "tap tests/*.js --100 -Rspec",
        prerelease: "npm test",
        release: "standard-version"
      },
      repository: {
        type: "git",
        url: "git://github.com/motdotla/dotenv.git"
      },
      funding: "https://github.com/motdotla/dotenv?sponsor=1",
      keywords: [
        "dotenv",
        "env",
        ".env",
        "environment",
        "variables",
        "config",
        "settings"
      ],
      readmeFilename: "README.md",
      license: "BSD-2-Clause",
      devDependencies: {
        "@definitelytyped/dtslint": "^0.0.133",
        "@types/node": "^18.11.3",
        decache: "^4.6.1",
        sinon: "^14.0.1",
        standard: "^17.0.0",
        "standard-markdown": "^7.1.0",
        "standard-version": "^9.5.0",
        tap: "^16.3.0",
        tar: "^6.1.11",
        typescript: "^4.8.4"
      },
      engines: {
        node: ">=12"
      },
      browser: {
        fs: false
      }
    };
  }
});

// node_modules/dotenv/lib/main.js
var require_main = __commonJS({
  "node_modules/dotenv/lib/main.js"(exports2, module2) {
    var fs2 = require("fs");
    var path2 = require("path");
    var os = require("os");
    var crypto4 = require("crypto");
    var packageJson = require_package();
    var version2 = packageJson.version;
    var LINE = /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/mg;
    function parse2(src) {
      const obj = {};
      let lines = src.toString();
      lines = lines.replace(/\r\n?/mg, "\n");
      let match;
      while ((match = LINE.exec(lines)) != null) {
        const key = match[1];
        let value = match[2] || "";
        value = value.trim();
        const maybeQuote = value[0];
        value = value.replace(/^(['"`])([\s\S]*)\1$/mg, "$2");
        if (maybeQuote === '"') {
          value = value.replace(/\\n/g, "\n");
          value = value.replace(/\\r/g, "\r");
        }
        obj[key] = value;
      }
      return obj;
    }
    function _parseVault(options) {
      const vaultPath = _vaultPath(options);
      const result = DotenvModule.configDotenv({ path: vaultPath });
      if (!result.parsed) {
        throw new Error(`MISSING_DATA: Cannot parse ${vaultPath} for an unknown reason`);
      }
      const keys = _dotenvKey(options).split(",");
      const length = keys.length;
      let decrypted;
      for (let i = 0; i < length; i++) {
        try {
          const key = keys[i].trim();
          const attrs = _instructions(result, key);
          decrypted = DotenvModule.decrypt(attrs.ciphertext, attrs.key);
          break;
        } catch (error) {
          if (i + 1 >= length) {
            throw error;
          }
        }
      }
      return DotenvModule.parse(decrypted);
    }
    function _log(message) {
      console.log(`[dotenv@${version2}][INFO] ${message}`);
    }
    function _warn(message) {
      console.log(`[dotenv@${version2}][WARN] ${message}`);
    }
    function _debug(message) {
      console.log(`[dotenv@${version2}][DEBUG] ${message}`);
    }
    function _dotenvKey(options) {
      if (options && options.DOTENV_KEY && options.DOTENV_KEY.length > 0) {
        return options.DOTENV_KEY;
      }
      if (process.env.DOTENV_KEY && process.env.DOTENV_KEY.length > 0) {
        return process.env.DOTENV_KEY;
      }
      return "";
    }
    function _instructions(result, dotenvKey) {
      let uri;
      try {
        uri = new URL(dotenvKey);
      } catch (error) {
        if (error.code === "ERR_INVALID_URL") {
          throw new Error("INVALID_DOTENV_KEY: Wrong format. Must be in valid uri format like dotenv://:key_1234@dotenv.org/vault/.env.vault?environment=development");
        }
        throw error;
      }
      const key = uri.password;
      if (!key) {
        throw new Error("INVALID_DOTENV_KEY: Missing key part");
      }
      const environment = uri.searchParams.get("environment");
      if (!environment) {
        throw new Error("INVALID_DOTENV_KEY: Missing environment part");
      }
      const environmentKey = `DOTENV_VAULT_${environment.toUpperCase()}`;
      const ciphertext = result.parsed[environmentKey];
      if (!ciphertext) {
        throw new Error(`NOT_FOUND_DOTENV_ENVIRONMENT: Cannot locate environment ${environmentKey} in your .env.vault file.`);
      }
      return { ciphertext, key };
    }
    function _vaultPath(options) {
      let dotenvPath = path2.resolve(process.cwd(), ".env");
      if (options && options.path && options.path.length > 0) {
        dotenvPath = options.path;
      }
      return dotenvPath.endsWith(".vault") ? dotenvPath : `${dotenvPath}.vault`;
    }
    function _resolveHome(envPath) {
      return envPath[0] === "~" ? path2.join(os.homedir(), envPath.slice(1)) : envPath;
    }
    function _configVault(options) {
      _log("Loading env from encrypted .env.vault");
      const parsed = DotenvModule._parseVault(options);
      let processEnv = process.env;
      if (options && options.processEnv != null) {
        processEnv = options.processEnv;
      }
      DotenvModule.populate(processEnv, parsed, options);
      return { parsed };
    }
    function configDotenv(options) {
      let dotenvPath = path2.resolve(process.cwd(), ".env");
      let encoding = "utf8";
      const debug2 = Boolean(options && options.debug);
      if (options) {
        if (options.path != null) {
          dotenvPath = _resolveHome(options.path);
        }
        if (options.encoding != null) {
          encoding = options.encoding;
        }
      }
      try {
        const parsed = DotenvModule.parse(fs2.readFileSync(dotenvPath, { encoding }));
        let processEnv = process.env;
        if (options && options.processEnv != null) {
          processEnv = options.processEnv;
        }
        DotenvModule.populate(processEnv, parsed, options);
        return { parsed };
      } catch (e) {
        if (debug2) {
          _debug(`Failed to load ${dotenvPath} ${e.message}`);
        }
        return { error: e };
      }
    }
    function config(options) {
      const vaultPath = _vaultPath(options);
      if (_dotenvKey(options).length === 0) {
        return DotenvModule.configDotenv(options);
      }
      if (!fs2.existsSync(vaultPath)) {
        _warn(`You set DOTENV_KEY but you are missing a .env.vault file at ${vaultPath}. Did you forget to build it?`);
        return DotenvModule.configDotenv(options);
      }
      return DotenvModule._configVault(options);
    }
    function decrypt(encrypted, keyStr) {
      const key = Buffer.from(keyStr.slice(-64), "hex");
      let ciphertext = Buffer.from(encrypted, "base64");
      const nonce = ciphertext.slice(0, 12);
      const authTag = ciphertext.slice(-16);
      ciphertext = ciphertext.slice(12, -16);
      try {
        const aesgcm = crypto4.createDecipheriv("aes-256-gcm", key, nonce);
        aesgcm.setAuthTag(authTag);
        return `${aesgcm.update(ciphertext)}${aesgcm.final()}`;
      } catch (error) {
        const isRange = error instanceof RangeError;
        const invalidKeyLength = error.message === "Invalid key length";
        const decryptionFailed = error.message === "Unsupported state or unable to authenticate data";
        if (isRange || invalidKeyLength) {
          const msg = "INVALID_DOTENV_KEY: It must be 64 characters long (or more)";
          throw new Error(msg);
        } else if (decryptionFailed) {
          const msg = "DECRYPTION_FAILED: Please check your DOTENV_KEY";
          throw new Error(msg);
        } else {
          console.error("Error: ", error.code);
          console.error("Error: ", error.message);
          throw error;
        }
      }
    }
    function populate(processEnv, parsed, options = {}) {
      const debug2 = Boolean(options && options.debug);
      const override = Boolean(options && options.override);
      if (typeof parsed !== "object") {
        throw new Error("OBJECT_REQUIRED: Please check the processEnv argument being passed to populate");
      }
      for (const key of Object.keys(parsed)) {
        if (Object.prototype.hasOwnProperty.call(processEnv, key)) {
          if (override === true) {
            processEnv[key] = parsed[key];
          }
          if (debug2) {
            if (override === true) {
              _debug(`"${key}" is already defined and WAS overwritten`);
            } else {
              _debug(`"${key}" is already defined and was NOT overwritten`);
            }
          }
        } else {
          processEnv[key] = parsed[key];
        }
      }
    }
    var DotenvModule = {
      configDotenv,
      _configVault,
      _parseVault,
      config,
      decrypt,
      parse: parse2,
      populate
    };
    module2.exports.configDotenv = DotenvModule.configDotenv;
    module2.exports._configVault = DotenvModule._configVault;
    module2.exports._parseVault = DotenvModule._parseVault;
    module2.exports.config = DotenvModule.config;
    module2.exports.decrypt = DotenvModule.decrypt;
    module2.exports.parse = DotenvModule.parse;
    module2.exports.populate = DotenvModule.populate;
    module2.exports = DotenvModule;
  }
});

// src/main.ts
var core = __toESM(require_core());
var import_octokit = __toESM(require_dist_node26());
var import_dotenv = __toESM(require_main());

// src/grouping.ts
function groupRunnersByLabel(runnersJson) {
  const groups = [];
  runnersJson.forEach((runner) => {
    runner.labels.forEach((label) => {
      const index = groups.findIndex((g) => g.name === label.name);
      const status = runner.status === "online" ? 1 : 0;
      if (index > -1) {
        groups[index].counter = groups[index].counter + 1;
        groups[index].status = groups[index].status + status;
      } else {
        groups.push({ name: label.name, counter: 1, status });
      }
    });
  });
  return groups;
}

// src/main.ts
var import_fs = __toESM(require("fs"));
var import_path = __toESM(require("path"));
import_dotenv.default.config();
async function run() {
  console.log("Starting");
  const accessToken = core.getInput("accessToken") || process.env.ACCESS_TOKEN || "";
  const repo = core.getInput("repo") || process.env.GITHUB_REPO || "";
  const organization = core.getInput("organization") || process.env.GITHUB_ORGANIZATION || "";
  if (!accessToken || accessToken === "") {
    core.setFailed(
      "Parameter 'accessToken' is required to load all actions from the organization or user account"
    );
    return;
  }
  if (organization === "") {
    core.setFailed(
      "Parameter 'organization' is required to load all runners from it. Please provide one of them."
    );
    return;
  }
  const apiUrl = process.env.GITHUB_API_URL || "https://api.github.com";
  core.debug(`Using API URL: ${apiUrl}`);
  const octokit = new import_octokit.Octokit({ auth: accessToken, baseUrl: apiUrl });
  let runnerInfo = {};
  if (organization !== "" && repo === "") {
    try {
      console.log(`Loading all runners from organization [${organization}]`);
      const data = await octokit.paginate("GET /orgs/{owner}/actions/runners", {
        owner: organization
      });
      if (data) {
        console.log(`Found ${data.length} runners at the org level`);
        core.debug("Found this data: " + JSON.stringify(data));
      }
      runnerInfo = data;
    } catch (error) {
      console.log(error);
      core.setFailed(
        `Could not authenticate with access token. Please check that it is correct and that it has the correct scope (see readme) to the organization: ${error}`
      );
      return;
    }
  }
  if (repo !== "") {
    try {
      console.log(`Loading all runners from repo [${organization}/${repo}]`);
      const data = await octokit.paginate("GET /repos/{owner}/{repo}/actions/runners", {
        owner: organization,
        repo
      });
      console.log(`Found ${data.length} runners at the repo level`);
      core.debug("Found this data: " + JSON.stringify(data));
      runnerInfo = data;
    } catch (error) {
      console.log(error);
      core.setFailed(
        `Could not authenticate with access token. Please check that it is correct and that it has the correct scope (see readme) on the repository: ${error}`
      );
      return;
    }
  }
  if (!runnerInfo) {
    core.setFailed(
      `Could not load any runners. Please check that the organization and repository are correct.`
    );
  } else {
    console.log(`Found ${runnerInfo.length} runners`);
    const json = JSON.stringify(runnerInfo);
    core.setOutput("runners", json);
    const fileName = import_path.default.resolve("runners.json");
    writeJsonToFile(json, fileName);
    core.setOutput("runners-file-location", fileName);
    const grouped = groupRunnersByLabel(runnerInfo);
    console.log(`Found ${grouped.length} groups`);
    const jsonGrouped = JSON.stringify(grouped);
    core.setOutput("grouped", jsonGrouped);
    const groupedFileName = import_path.default.resolve("runners-grouped.json");
    writeJsonToFile(jsonGrouped, groupedFileName);
    core.setOutput("grouped-file-location", groupedFileName);
  }
  function writeJsonToFile(json, fileName) {
    import_fs.default.writeFileSync(fileName, json);
  }
}
run();
/*! Bundled license information:

is-plain-object/dist/is-plain-object.js:
  (*!
   * is-plain-object <https://github.com/jonschlinkert/is-plain-object>
   *
   * Copyright (c) 2014-2017, Jon Schlinkert.
   * Released under the MIT License.
   *)
*/
