package com.lauriewired

import com.lauriewired.context.GhidraContext
import com.sun.net.httpserver.{HttpExchange, HttpServer}
import java.net.{InetSocketAddress, URLDecoder}
import java.nio.charset.StandardCharsets
import java.util.concurrent.{ExecutorService, Executors}

class GhidraMCPServer(analysisService: GhidraAnalysisService, context: GhidraContext):
  private var server: Option[HttpServer] = None
  private var executor: Option[ExecutorService] = None

  def start(): Unit = start(0)

  def start(port: Int): Unit =
    val s = HttpServer.create(new InetSocketAddress(port), 0)
    setupEndpoints(s)
    val exec = Executors.newCachedThreadPool(r => {
      val t = new Thread(r)
      t.setDaemon(true)
      t
    })
    s.setExecutor(exec)
    s.start()
    server = Some(s)
    executor = Some(exec)

  def getPort(): Int = server.map(_.getAddress.getPort).getOrElse(-1)

  def stop(): Unit =
    server.foreach { s =>
      s.stop(1)
      println("GhidraMCP HTTP server stopped")
    }
    executor.foreach(_.shutdownNow())
    server = None
    executor = None

  private def setupEndpoints(s: HttpServer): Unit =
    def listEndpoint(path: String, fn: (Int, Int) => Either[String, List[String]]): Unit =
      s.createContext(path, exchange => {
        val q = parseQueryParams(exchange)
        sendResponse(exchange, fn(parseInt(q.get("offset"), 0), parseInt(q.get("limit"), 100)).fold(identity, _.mkString("\n")))
      })

    listEndpoint("/methods",        analysisService.getAllFunctionNames)
    listEndpoint("/classes",        analysisService.getAllClassNames)
    listEndpoint("/segments",       analysisService.listSegments)
    listEndpoint("/imports",        analysisService.listImports)
    listEndpoint("/exports",        analysisService.listExports)
    listEndpoint("/namespaces",     analysisService.listNamespaces)
    listEndpoint("/data",           analysisService.listDefinedData)
    listEndpoint("/list_functions", analysisService.listFunctions)
    listEndpoint("/strings",        (o, l) => analysisService.getStrings(o, l))

    s.createContext("/searchFunctions", exchange => {
      val q = parseQueryParams(exchange)
      val result = analysisService.searchFunctionsByName(
        q.getOrElse("query", ""), parseInt(q.get("offset"), 0), parseInt(q.get("limit"), 100))
      sendResponse(exchange, result.fold(identity, _.mkString("\n")))
    })

    s.createContext("/xrefs_to", exchange => {
      val q = parseQueryParams(exchange)
      val result = analysisService.getXrefsTo(
        q.getOrElse("address", ""), parseInt(q.get("offset"), 0), parseInt(q.get("limit"), 100))
      sendResponse(exchange, result.fold(identity, _.mkString("\n")))
    })

    s.createContext("/xrefs_from", exchange => {
      val q = parseQueryParams(exchange)
      val result = analysisService.getXrefsFrom(
        q.getOrElse("address", ""), parseInt(q.get("offset"), 0), parseInt(q.get("limit"), 100))
      sendResponse(exchange, result.fold(identity, _.mkString("\n")))
    })

    s.createContext("/function_xrefs", exchange => {
      val q = parseQueryParams(exchange)
      val result = analysisService.getFunctionXrefs(
        q.getOrElse("function_name", ""), parseInt(q.get("offset"), 0), parseInt(q.get("limit"), 100))
      sendResponse(exchange, result.fold(identity, _.mkString("\n")))
    })

    s.createContext("/decompile", exchange => {
      val name = new String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
      sendResponse(exchange, analysisService.decompileFunctionByName(name))
    })

    s.createContext("/decompile_function", exchange => {
      sendResponse(exchange, analysisService.decompileFunctionByAddress(
        parseQueryParams(exchange).getOrElse("address", "")))
    })

    s.createContext("/disassemble_function", exchange => {
      sendResponse(exchange, analysisService.disassembleFunction(
        parseQueryParams(exchange).getOrElse("address", "")))
    })

    s.createContext("/renameFunction", exchange => {
      val p = parsePostParams(exchange)
      sendResponse(exchange, analysisService.renameFunction(
        p.getOrElse("oldName", ""), p.getOrElse("newName", "")).fold(identity, identity))
    })

    s.createContext("/rename_function_by_address", exchange => {
      val p = parsePostParams(exchange)
      sendResponse(exchange, analysisService.renameFunctionByAddress(
        p.getOrElse("function_address", ""), p.getOrElse("new_name", "")).fold(identity, identity))
    })

    s.createContext("/create_or_update_data_item", exchange => {
      val p = parsePostParams(exchange)
      sendResponse(exchange, analysisService.createOrUpdateDataItem(
        p.getOrElse("address", ""), p.getOrElse("data_type", ""), p.getOrElse("new_name", "")).fold(identity, identity))
    })

    s.createContext("/get_function_by_address", exchange => {
      sendResponse(exchange, analysisService.getFunctionByAddress(
        parseQueryParams(exchange).getOrElse("address", "")))
    })

    s.createContext("/get_current_address", exchange =>
      sendResponse(exchange, analysisService.getCurrentAddress()))

    s.createContext("/get_current_function", exchange =>
      sendResponse(exchange, analysisService.getCurrentFunction()))

    s.createContext("/goto", exchange => {
      try
        if exchange.getRequestMethod == "POST" then
          val result = analysisService.goToTarget(parsePostParams(exchange).getOrElse("target", ""))
          sendResponse(exchange, if result != null then result else "Error: goto returned no response")
        else
          exchange.sendResponseHeaders(405, -1)
      catch case e: Exception =>
        try sendResponse(exchange, s"Error: goto endpoint failed: ${e.getMessage}")
        catch case _: Exception => System.err.println(s"Failed to send goto error response: ${e.getMessage}")
    })

    s.createContext("/status", exchange => {
      val gui = context.isGuiMode()
      val programName = context.getCurrentProgram()
        .map(p => Option(p.getDomainFile).map(_.getName).getOrElse(p.getName))
        .orNull
      sendJsonResponse(exchange, Map(
        "mode"           -> (if gui then "Headed (GUI)" else "Headless"),
        "gui"            -> gui,
        "programName"    -> programName,
        "programLoaded"  -> (programName != null),
        "currentAddress" -> analysisService.getCurrentAddress()
      ))
    })

    s.createContext("/run_script", exchange => {
      if exchange.getRequestMethod == "POST" then
        val p = parsePostParams(exchange)
        sendResponse(exchange, analysisService.runScript(p.getOrElse("name", ""), p.getOrElse("script", "")))
    })

    s.createContext("/export_functions", exchange => {
      if exchange.getRequestMethod == "GET" then
        sendJsonResponse(exchange, Map("functions" -> analysisService.exportFunctions()))
      else
        exchange.sendResponseHeaders(405, -1)
    })

    s.createContext("/set_decompiler_comment", exchange => {
      if exchange.getRequestMethod == "POST" then
        val p = parsePostParams(exchange)
        sendJsonResponse(exchange, Map("success" ->
          analysisService.setDecompilerComment(p.getOrElse("address", ""), p.getOrElse("comment", ""))))
      else
        exchange.sendResponseHeaders(405, -1)
    })

    s.createContext("/set_disassembly_comment", exchange => {
      if exchange.getRequestMethod == "POST" then
        val p = parsePostParams(exchange)
        sendJsonResponse(exchange, Map("success" ->
          analysisService.setDisassemblyComment(p.getOrElse("address", ""), p.getOrElse("comment", ""))))
      else
        exchange.sendResponseHeaders(405, -1)
    })

    s.createContext("/rename_variable", exchange => {
      if exchange.getRequestMethod == "POST" then
        val p = parsePostParams(exchange)
        sendJsonResponse(exchange, Map("result" -> analysisService.renameVariableInFunction(
          p.getOrElse("function", ""), p.getOrElse("old_name", ""), p.getOrElse("new_name", ""))))
      else
        exchange.sendResponseHeaders(405, -1)
    })

    s.createContext("/renameVariable", exchange => {
      val p = parsePostParams(exchange)
      sendResponse(exchange, analysisService.renameVariableInFunction(
        p.getOrElse("function", ""), p.getOrElse("old_name", ""), p.getOrElse("new_name", "")))
    })

    s.createContext("/set_local_variable_type", exchange => {
      if exchange.getRequestMethod == "POST" then
        val p = parsePostParams(exchange)
        sendResponse(exchange, analysisService.setLocalVariableType(
          p.getOrElse("function_address", ""), p.getOrElse("variable_name", ""), p.getOrElse("new_type", "")))
      else
        exchange.sendResponseHeaders(405, -1)
    })

    s.createContext("/set_function_prototype", exchange => {
      val p = parsePostParams(exchange)
      val addr = p.getOrElse("function_address", "")
      val proto = p.getOrElse("prototype", "")
      if addr.isEmpty || proto.isEmpty then
        sendResponse(exchange, "Error: function_address and prototype parameters are required")
      else
        sendResponse(exchange, analysisService.setFunctionPrototype(addr, proto))
    })

    s.createContext("/export_data", exchange => {
      if exchange.getRequestMethod == "GET" then
        val q = parseQueryParams(exchange)
        val addr = q.getOrElse("address", "")
        val lenStr = q.getOrElse("length", "")
        if addr.isEmpty || lenStr.isEmpty then
          sendResponse(exchange, "Error: address and length parameters are required")
        else
          scala.util.Try(lenStr.toInt).fold(
            _ => sendResponse(exchange, s"Error: Invalid length parameter: $lenStr"),
            len => sendResponse(exchange, analysisService.exportData(addr, len))
          )
      else
        exchange.sendResponseHeaders(405, -1)
    })

    s.createContext("/create_type_from_c_definition", exchange => {
      sendResponse(exchange, analysisService.createTypeFromCDefinition(
        parsePostParams(exchange).getOrElse("definition", "")))
    })

  // Response Helpers
  // ================

  private def sendResponse(exchange: HttpExchange, body: String): Unit =
    val bytes = body.getBytes(StandardCharsets.UTF_8)
    exchange.getResponseHeaders.set("Content-Type", "text/plain; charset=utf-8")
    exchange.sendResponseHeaders(200, bytes.length)
    val os = exchange.getResponseBody
    try os.write(bytes)
    finally os.close()

  private def sendJsonResponse(exchange: HttpExchange, response: Map[String, Any]): Unit =
    val json = response.map { (k, v) =>
      val encoded = v match
        case s: String  => s""""${escapeJson(s)}""""
        case b: Boolean => b.toString
        case null       => "null"
        case other      => s""""${escapeJson(other.toString)}""""
      s""""$k":$encoded"""
    }.mkString("{", ",", "}")
    val bytes = json.getBytes(StandardCharsets.UTF_8)
    exchange.getResponseHeaders.set("Content-Type", "application/json; charset=utf-8")
    exchange.sendResponseHeaders(200, bytes.length)
    val os = exchange.getResponseBody
    try os.write(bytes)
    finally os.close()

  private def escapeJson(s: String): String =
    s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")

  // Request Parsing Helpers
  // =======================

  private def parseQueryParams(exchange: HttpExchange): Map[String, String] =
    Option(exchange.getRequestURI.getQuery)
      .map(_.split("&").flatMap(decodePair).toMap)
      .getOrElse(Map.empty)

  private def parsePostParams(exchange: HttpExchange): Map[String, String] =
    new String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
      .split("&").flatMap(decodePair).toMap

  private def decodePair(pair: String): Option[(String, String)] =
    pair.split("=", 2) match
      case Array(k, v) =>
        try Some(URLDecoder.decode(k, StandardCharsets.UTF_8) -> URLDecoder.decode(v, StandardCharsets.UTF_8))
        catch case _: Exception => None
      case _ => None

  private def parseInt(value: Option[String], default: Int): Int =
    value.flatMap(s => scala.util.Try(s.trim.toInt).toOption).getOrElse(default)
