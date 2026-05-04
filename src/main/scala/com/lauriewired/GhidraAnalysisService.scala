package com.lauriewired

import com.lauriewired.context.GhidraContext
import ghidra.program.model.listing.*
import ghidra.program.model.address.*
import ghidra.program.model.symbol.*
import ghidra.program.model.data.*
import ghidra.app.decompiler.*
import ghidra.app.services.GoToService
import ghidra.app.util.parser.FunctionSignatureParser
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd
import ghidra.app.script.*
import ghidra.framework.plugintool.PluginTool
import ghidra.program.util.ProgramLocation
import ghidra.util.Msg
import ghidra.util.task.TaskMonitor
import generic.jar.ResourceFile
import java.io.*
import scala.jdk.CollectionConverters.*

class GhidraAnalysisService(context: GhidraContext):

  // Script Execution
  // ================

  def runScript(scriptName: String, scriptSource: String): String =
    if scriptSource == null || scriptSource.trim.isEmpty then
      try
        val existing = GhidraScriptUtil.findScriptByName(scriptName)
        if existing != null && existing.exists then
          loadScript(existing)
            .flatMap(executeScript(_, scriptName, deleteAfter = false))
            .fold(identity, identity)
        else s"Error: Script not found: $scriptName"
      catch case e: Exception => s"Error locating existing script: ${e.getMessage}"
    else
      (for
        scriptFile <- createScriptFile(scriptName, scriptSource)
        script     <- loadScript(scriptFile)
        output     <- executeScript(script, scriptName, deleteAfter = true)
      yield output).fold(identity, identity)

  private def createScriptFile(scriptName: String, scriptSource: String): Either[String, ResourceFile] =
    try
      val scriptDir = GhidraScriptUtil.getUserScriptDirectory()
      val targetDir = scriptDir.getFile(false)
      val scriptFile = new File(targetDir, scriptName)
      if scriptFile.exists then Left(s"Script already exists: $scriptName")
      else
        val writer = new FileWriter(scriptFile)
        try writer.write(scriptSource)
        finally writer.close()
        Right(new ResourceFile(scriptFile))
    catch case e: IOException =>
      Msg.error(this, s"Error writing script file: ${e.getMessage}")
      Left(s"Failed to create script file: ${e.getMessage}")

  private def loadScript(scriptFile: ResourceFile): Either[String, GhidraScript] =
    Iterator.range(0, 3)
      .map { attempt =>
        try
          if attempt > 0 then Thread.sleep(1000)
          val provider = GhidraScriptUtil.getProvider(scriptFile)
          Right(provider.getScriptInstance(scriptFile, new PrintWriter(System.err)))
        catch case e: Exception =>
          Msg.error(this, s"Script load attempt ${attempt + 1} failed: ${e.getMessage}")
          Left(e.getMessage)
      }
      .find(_.isRight)
      .getOrElse(Left("No attempts made"))

  private def executeScript(script: GhidraScript, scriptName: String, deleteAfter: Boolean): Either[String, String] =
    try
      val sw = new StringWriter()
      script.execute(getState(), TaskMonitor.DUMMY, new PrintWriter(sw))
      Right(sw.toString)
    catch case e: Exception => Left(s"Error running script: ${e.getMessage}")
    finally
      if deleteAfter then cleanupScriptFile(scriptName)

  private def cleanupScriptFile(scriptName: String): Unit =
    try
      val scriptFile = GhidraScriptUtil.findScriptByName(scriptName)
      if scriptFile != null && scriptFile.exists then scriptFile.delete()
    catch case e: Exception =>
      Msg.error(this, s"Error cleaning up script file: ${e.getMessage}")

  private def getState(): GhidraState =
    val currentProgram = context.getCurrentProgram().orNull
    val currentAddress = context.getCurrentAddress().orNull
    val loc =
      if currentProgram != null && currentAddress != null
      then new ProgramLocation(currentProgram, currentAddress)
      else null
    val tool = context.getTool().orNull
    val project = if tool != null then tool.getProject() else null
    new GhidraState(tool, project, currentProgram, loc, null, null)

  // Function Listing / Search
  // =========================

  def getAllFunctionNames(offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      Right(streamFunctions(program).map(_.getName).drop(offset).take(limit).toList)
    }.getOrElse(Left("No program loaded"))

  def getAllClassNames(offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      val classNames = program.getSymbolTable().getAllSymbols(true).iterator().asScala
        .flatMap(sym => Option(sym.getParentNamespace()).filter(!_.isGlobal).map(_.getName))
        .toSet
      Right(classNames.toList.sorted.drop(offset).take(limit))
    }.getOrElse(Left("No program loaded"))

  def listFunctions(offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      Right(streamFunctions(program)
        .map(f => s"${f.getName} @ ${f.getEntryPoint}")
        .drop(offset).take(limit).toList)
    }.getOrElse(Left("No program loaded"))

  def searchFunctionsByName(searchTerm: String, offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      Right(streamFunctions(program)
        .filter(_.getName.toLowerCase.contains(searchTerm.toLowerCase))
        .map(_.getName)
        .drop(offset).take(limit).toList)
    }.getOrElse(Left("No program loaded"))

  def getFunctionByAddress(addressStr: String): String =
    context.withProgram { program =>
      (for
        addr <- parseAddress(program, addressStr)
        func <- findFunctionByAddress(program, addr)
      yield s"Function: ${func.getName} @ ${func.getEntryPoint}")
        .fold(err => s"No function found at address: $err", identity)
    }.getOrElse("No program loaded")

  // Decompilation
  // =============

  def decompileFunctionByName(name: String): String =
    context.withProgram { program =>
      (for
        func   <- findFunctionByName(program, name)
        output <- decompileFunction(program, func)
      yield output).fold(err => s"Function not found: $err", identity)
    }.getOrElse("No program loaded")

  def decompileFunctionByAddress(addressStr: String): String =
    context.withProgram { program =>
      (for
        addr   <- parseAddress(program, addressStr)
        func   <- findFunctionByAddress(program, addr)
        output <- decompileFunction(program, func)
      yield output).fold(err => s"Function not found at address: $err", identity)
    }.getOrElse("No program loaded")

  def disassembleFunction(addressStr: String): String =
    context.withProgram { program =>
      (for
        addr <- parseAddress(program, addressStr)
        func <- findFunctionByAddress(program, addr)
      yield disassembleFunctionInstructions(program, func))
        .fold(err => s"Function not found at address: $err", identity)
    }.getOrElse("No program loaded")

  // Renaming
  // ========

  def renameFunction(oldName: String, newName: String): Either[String, String] =
    context.withProgram { program =>
      val tx = program.startTransaction("Rename function")
      try
        findFunctionByName(program, oldName)
          .flatMap { func =>
            try
              if tryRename(func, newName) then Right("Renamed successfully")
              else Left("Failed to rename function")
            catch case e: Exception => Left(s"Failed to rename function: ${e.getMessage}")
          }
          .left.map(_ => s"Function '$oldName' not found")
      finally
        program.endTransaction(tx, true)
    }.getOrElse(Left("No program loaded"))

  def renameFunctionByAddress(addressStr: String, newName: String): Either[String, String] =
    context.withProgram { program =>
      val tx = program.startTransaction("Rename function by address")
      try
        parseAddress(program, addressStr)
          .flatMap(findFunctionByAddress(program, _))
          .flatMap { func =>
            try
              if tryRename(func, newName) then Right("Renamed successfully")
              else Left("Failed to rename function")
            catch case e: Exception => Left(s"Failed to rename function: ${e.getMessage}")
          }
          .left.map(_ => s"No function at address: $addressStr")
      finally
        program.endTransaction(tx, true)
    }.getOrElse(Left("No program loaded"))

  def renameVariableInFunction(functionName: String, oldName: String, newName: String): String =
    context.withProgram { program =>
      findFunctionByName(program, functionName).flatMap { func =>
        val decomp = new DecompInterface()
        decomp.openProgram(program)
        val results = decomp.decompileFunction(func, 30, context.getTaskMonitor())
        if results == null || !results.decompileCompleted() then
          Left(s"Decompilation failed for function $functionName")
        else
          Option(results.getHighFunction)
            .filter(_.getLocalSymbolMap != null)
            .toRight(s"No local symbol map available for function $functionName")
            .flatMap { hf =>
              val localSymbolMap = hf.getLocalSymbolMap
              val symbols = localSymbolMap.getSymbols.asScala.toList
              if symbols.exists(_.getName == newName) then
                Left(s"Error: A variable with name '$newName' already exists in this function")
              else
                symbols.find(_.getName == oldName)
                  .toRight(s"Variable '$oldName' not found in function '$functionName'")
                  .flatMap { highSymbol =>
                    val tx = program.startTransaction("Rename variable")
                    try
                      if checkFullCommit(highSymbol, hf) then
                        ghidra.program.model.pcode.HighFunctionDBUtil.commitParamsToDatabase(
                          hf, false,
                          ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT,
                          func.getSignatureSource)
                      ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(
                        highSymbol, newName, null, SourceType.USER_DEFINED)
                      Right("Variable renamed successfully")
                    catch case e: Exception => Left(s"Failed to rename variable: ${e.getMessage}")
                    finally program.endTransaction(tx, true)
                  }
            }
      }.fold(err => s"Function '$functionName' not found: $err", identity)
    }.getOrElse("No program loaded")

  private def checkFullCommit(
      highSymbol: ghidra.program.model.pcode.HighSymbol,
      hfunction: ghidra.program.model.pcode.HighFunction): Boolean =
    if highSymbol != null && !highSymbol.isParameter then false
    else
      val function = hfunction.getFunction
      val parameters = function.getParameters
      val localSymbolMap = hfunction.getLocalSymbolMap
      val numParams = localSymbolMap.getNumParams
      numParams != parameters.length ||
      (0 until numParams).exists { i =>
        val param = localSymbolMap.getParamSymbol(i)
        param.getCategoryIndex != i ||
        param.getStorage.compareTo(parameters(i).getVariableStorage) != 0
      }

  // Listing Operations
  // ==================

  def listSegments(offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      Right(program.getMemory().getBlocks().toList
        .map(b => s"${b.getName}: ${b.getStart} - ${b.getEnd}")
        .drop(offset).take(limit))
    }.getOrElse(Left("No program loaded"))

  def listImports(offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      Right(program.getSymbolTable().getExternalSymbols().iterator().asScala.toList
        .map(sym => s"${sym.getName} -> ${sym.getAddress}")
        .drop(offset).take(limit))
    }.getOrElse(Left("No program loaded"))

  def listExports(offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      Right(program.getSymbolTable().getAllSymbols(true).iterator().asScala.toList
        .filter(_.isExternalEntryPoint)
        .map(sym => s"${sym.getName} -> ${sym.getAddress}")
        .drop(offset).take(limit))
    }.getOrElse(Left("No program loaded"))

  def listNamespaces(offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      val namespaces = program.getSymbolTable().getAllSymbols(true).iterator().asScala
        .flatMap(sym =>
          Option(sym.getParentNamespace())
            .filterNot(_.isInstanceOf[GlobalNamespace])
            .map(_.getName))
        .toSet
      Right(namespaces.toList.sorted.drop(offset).take(limit))
    }.getOrElse(Left("No program loaded"))

  // Data Operations
  // ===============

  def listDefinedData(offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      try
        val lines = program.getMemory().getBlocks().toList.flatMap { block =>
          program.getListing().getDefinedData(block.getStart, true).iterator().asScala
            .filter(data => block.contains(data.getAddress))
            .map { data =>
              val label = Option(data.getLabel).getOrElse("(unnamed)")
              val typeName = Option(data.getDataType).flatMap { dt =>
                Option(dt.getDisplayName).filter(_.trim.nonEmpty)
                  .orElse(Option(dt.getName).filter(_.trim.nonEmpty))
              }.getOrElse("(unknown)")
              val valRepr = data.getDefaultValueRepresentation()
              s"${data.getAddress}: ${escapeNonAscii(label)} (${escapeNonAscii(typeName)}) = ${escapeNonAscii(valRepr)}"
            }
        }
        Right(lines.drop(offset).take(limit))
      catch case e: Exception => Left(s"Error listing defined data: ${e.getMessage}")
    }.getOrElse(Left("No program loaded"))

  def createOrUpdateDataItem(addressStr: String, dataTypeName: String, newName: String): Either[String, String] =
    val normalizedTypeName = Option(dataTypeName).map(_.trim).getOrElse("")
    val normalizedNewName  = Option(newName).map(_.trim).getOrElse("")
    val hasType = normalizedTypeName.nonEmpty
    val hasName = normalizedNewName.nonEmpty

    if !hasType && !hasName then Left("At least one of data_type or new_name is required")
    else context.withProgram { program =>
      val tx = program.startTransaction("Create or update data item")
      var txSuccess = false
      try
        val result = parseAddress(program, addressStr).flatMap { addr =>
          val existingData = program.getListing().getDefinedDataAt(addr)
          if !hasType && existingData == null then
            Left(s"No data at address: $addr (data_type required to create)")
          else
            var changes = Vector.empty[String]

            val afterType: Either[String, Unit] =
              if !hasType then Right(())
              else resolveDataType(program.getDataTypeManager(), normalizedTypeName).flatMap { resolvedType =>
                val length = resolvedType.getLength
                if length <= 0 then Left(s"Data type '${resolvedType.getName}' has unsupported length: $length")
                else try
                  val endAddr = addr.addNoWrap(length - 1L)
                  program.getListing().clearCodeUnits(addr, endAddr, false)
                  Option(program.getListing().createData(addr, resolvedType)) match
                    case None => Left(s"Failed to create data at address: $addr")
                    case Some(_) =>
                      val displayName = Option(resolvedType.getDisplayName).getOrElse(resolvedType.getName)
                      changes = changes :+ (
                        if existingData == null then s"created data type '$displayName'"
                        else s"updated data type to '$displayName'")
                      Right(())
                catch
                  case e: AddressOverflowException =>
                    Left(s"Data range overflows address space: ${e.getMessage}")
                  case e: Exception =>
                    Left(s"Error creating/updating data at $addr: ${e.getMessage}")
              }

            afterType.flatMap { _ =>
              if !hasName then Right(s"Successfully ${changes.mkString(" and ")} at $addr")
              else try
                val symTable = program.getSymbolTable()
                Option(symTable.getPrimarySymbol(addr)) match
                  case Some(sym) => sym.setName(normalizedNewName, SourceType.USER_DEFINED)
                  case None      => symTable.createLabel(addr, normalizedNewName, SourceType.USER_DEFINED)
                changes = changes :+ s"set label to '$normalizedNewName'"
                Right(s"Successfully ${changes.mkString(" and ")} at $addr")
              catch case e: Exception =>
                Left(s"Error renaming data label at $addr: ${e.getMessage}")
            }
        }
        txSuccess = result.isRight
        result
      finally
        program.endTransaction(tx, txSuccess)
    }.getOrElse(Left("No program loaded"))

  // Current Location (GUI-specific)
  // ================================

  def getCurrentAddress(): String =
    context.getCurrentAddress()
      .map(_.toString)
      .getOrElse(if context.isGuiMode() then "No current location" else "Not available in headless mode")

  def getCurrentFunction(): String =
    context.getCurrentFunction()
      .getOrElse(if context.isGuiMode() then "No function at current location" else "Not available in headless mode")

  def goToTarget(target: String): String =
    try
      if target == null || target.trim.isEmpty then return "Error: target is required"
      if !context.isGuiMode() then return "Not available in headless mode"
      val normalizedTarget = target.trim
      context.withProgram { program =>
        context.getTool() match
          case None => "Error: GoTo service unavailable"
          case Some(tool) =>
            Option(tool.getService(classOf[GoToService])) match
              case None => "Error: GoTo service unavailable"
              case Some(goToService) =>
                parseAddress(program, normalizedTarget) match
                  case Right(address) =>
                    if goToService.goTo(address, program) then s"Navigated to address: $address"
                    else s"Error: navigation failed for target: $normalizedTarget"
                  case Left(_) =>
                    findFunctionByName(program, normalizedTarget) match
                      case Left(_) => s"Function not found: $normalizedTarget"
                      case Right(function) =>
                        val functionAddress = function.getEntryPoint
                        if goToService.goTo(functionAddress, program) then
                          s"Navigated to function: ${function.getName} @ $functionAddress"
                        else s"Error: navigation failed for target: $normalizedTarget"
      }.getOrElse("No program loaded")
    catch case e: Exception => s"Error: goto failed: ${e.getMessage}"

  // Cross-Reference Operations
  // ==========================

  def getXrefsTo(addressStr: String, offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      parseAddress(program, addressStr)
        .map { addr =>
          program.getReferenceManager().getReferencesTo(addr).iterator().asScala.map { ref =>
            val fromAddr = ref.getFromAddress
            val refType  = ref.getReferenceType
            val funcInfo = Option(program.getFunctionManager().getFunctionContaining(fromAddr))
              .map(f => s" in ${f.getName}").getOrElse("")
            val label    = getPrimarySymbolLabel(program, fromAddr).fold(_ => "", identity)
            val labelInfo = if label.isEmpty then "" else s" [label:$label]"
            s"From $fromAddr$funcInfo$labelInfo [${refType.getName}]"
          }.drop(offset).take(limit).toList
        }
        .left.map(_ => s"Invalid address: $addressStr")
    }.getOrElse(Left("No program loaded"))

  def getXrefsFrom(addressStr: String, offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      parseAddress(program, addressStr)
        .map { addr =>
          program.getReferenceManager().getReferencesFrom(addr).toList.map { ref =>
            val toAddr  = ref.getToAddress
            val refType = ref.getReferenceType
            val funcInfo = Option(program.getFunctionManager().getFunctionContaining(toAddr))
              .map(f => s" in ${f.getName}").getOrElse("")
            val label    = getPrimarySymbolLabel(program, toAddr).fold(_ => "", identity)
            val labelInfo = if label.isEmpty then "" else s" [label:$label]"
            s"To $toAddr$funcInfo$labelInfo [${refType.getName}]"
          }.drop(offset).take(limit)
        }
        .left.map(_ => s"Invalid address: $addressStr")
    }.getOrElse(Left("No program loaded"))

  def getFunctionXrefs(functionName: String, offset: Int, limit: Int): Either[String, List[String]] =
    context.withProgram { program =>
      findFunctionByName(program, functionName).map { func =>
        val body = func.getBody
        body.getAddressRanges.iterator().asScala.flatMap { range =>
          Iterator.iterate(range.getMinAddress)(_.next)
            .takeWhile(addr => addr != null && range.contains(addr))
            .flatMap { addr =>
              program.getReferenceManager().getReferencesFrom(addr)
                .filter(_.getReferenceType.isCall)
                .map { ref =>
                  val toAddr = ref.getToAddress
                  val target = Option(program.getFunctionManager().getFunctionContaining(toAddr))
                    .map(_.getName).getOrElse(toAddr.toString)
                  s"$addr calls $target"
                }
            }
        }.drop(offset).take(limit).toList
      }
    }.getOrElse(Left("No program loaded"))

  // String Analysis
  // ===============

  def getStrings(offset: Int, limit: Int): Either[String, List[String]] =
    getStrings(offset, limit, None)

  def getStrings(offset: Int, limit: Int, filter: String): Either[String, List[String]] =
    getStrings(offset, limit, Option(filter))

  private def getStrings(offset: Int, limit: Int, filter: Option[String]): Either[String, List[String]] =
    context.withProgram { program =>
      try
        val strings = program.getMemory().getBlocks().toList
          .filter(_.isInitialized)
          .flatMap { block =>
            program.getListing().getDefinedData(block.getStart, true).iterator().asScala
              .filter(_.hasStringValue)
              .collect {
                case data if filter.forall(f => data.getDefaultValueRepresentation().toLowerCase.contains(f.toLowerCase)) =>
                  s"${data.getAddress}: ${escapeNonAscii(data.getDefaultValueRepresentation())}"
              }
          }
        Right(strings.drop(offset).take(limit))
      catch case e: Exception => Left(s"Error listing strings: ${e.getMessage}")
    }.getOrElse(Left("No program loaded"))

  // Comment Operations
  // ==================

  def setDecompilerComment(addressStr: String, comment: String): Boolean =
    setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment")

  def setDisassemblyComment(addressStr: String, comment: String): Boolean =
    setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment")

  private def setCommentAtAddress(addressStr: String, comment: String, commentType: Int, transactionName: String): Boolean =
    context.withProgram { program =>
      val tx = program.startTransaction(transactionName)
      try
        parseAddress(program, addressStr)
          .map { addr =>
            Option(program.getListing().getCodeUnitAt(addr)) match
              case None =>
                context.showError(s"No code unit found at address $addr")
                false
              case Some(cu) =>
                try
                  cu.setComment(commentType, comment)
                  true
                catch case e: Exception =>
                  context.showError(s"Error setting comment: ${e.getMessage}")
                  false
          }
          .fold(err => { context.showError(err); false }, identity)
      finally
        program.endTransaction(tx, true)
    }.getOrElse(false)

  // Variable / Type Operations
  // ==========================

  def setLocalVariableType(functionAddress: String, variableName: String, newType: String): String =
    context.withProgram { program =>
      val tx = program.startTransaction("Set variable type")
      try
        (for
          addr <- parseAddress(program, functionAddress)
          func <- findFunctionByAddress(program, addr)
          hf   <- {
            val decomp = new DecompInterface()
            decomp.openProgram(program)
            val results = decomp.decompileFunction(func, 30, context.getTaskMonitor())
            if results == null || !results.decompileCompleted() then
              Left(s"Decompilation failed for function at $functionAddress")
            else
              Option(results.getHighFunction)
                .toRight(s"No high function available for $functionAddress")
          }
          sym  <- findSymbolByName(hf, variableName)
          dt   <- resolveDataType(program.getDataTypeManager(), newType)
          msg  <- try
            ghidra.program.model.pcode.HighFunctionDBUtil.updateDBVariable(
              sym, sym.getName, dt, SourceType.USER_DEFINED)
            Right(s"Variable type set successfully to ${dt.getName}")
          catch case e: Exception => Left(s"Failed to update variable: ${e.getMessage}")
        yield msg)
          .fold(err => s"No function at address: $err", identity)
      catch case e: Exception => s"Error setting variable type: ${e.getMessage}"
      finally program.endTransaction(tx, true)
    }.getOrElse("No program loaded")

  private def findSymbolByName(
      highFunction: ghidra.program.model.pcode.HighFunction,
      variableName: String): Either[String, ghidra.program.model.pcode.HighSymbol] =
    highFunction.getLocalSymbolMap.getSymbols.asScala
      .find(_.getName == variableName)
      .toRight(s"Variable '$variableName' not found")

  private def resolveDataType(dtm: DataTypeManager, typeName: String): Either[String, DataType] =
    val fromParser =
      try
        val parser = new ghidra.app.util.cparser.C.CParser(dtm)
        Option(parser.parse(typeName)).map(Right(_))
      catch case _ => None
    fromParser.getOrElse {
      Option(dtm.getDataType("/" + typeName)).map(Right(_)).getOrElse {
        dtm.getAllDataTypes.asScala
          .find(_.getName.equalsIgnoreCase(typeName))
          .toRight(s"Could not resolve data type: $typeName")
      }
    }

  // Function Prototype
  // ==================

  def setFunctionPrototype(functionAddress: String, prototype: String): String =
    context.withProgram { program =>
      (for
        addr <- parseAddress(program, functionAddress)
        func <- findFunctionByAddress(program, addr)
      yield
        val tx = program.startTransaction("Set function prototype")
        var success = false
        try
          val parser = new FunctionSignatureParser(program.getDataTypeManager(), null)
          Option(parser.parse(null, prototype)) match
            case None => s"Failed to parse function prototype: $prototype"
            case Some(sig) =>
              val cmd = new ApplyFunctionSignatureCmd(func.getEntryPoint, sig, SourceType.USER_DEFINED)
              success = cmd.applyTo(program, context.getTaskMonitor())
              if success then "Function prototype updated successfully"
              else s"Failed to apply function signature: ${cmd.getStatusMsg}"
        catch case e: Exception => s"Error setting function prototype: ${e.getMessage}"
        finally program.endTransaction(tx, success)
      ).fold(err => s"Function not found at address: $err", identity)
    }.getOrElse("No program loaded")

  // Type Creation / Data Export
  // ===========================

  def createTypeFromCDefinition(cDefinition: String): String =
    context.withProgram { program =>
      val tx = program.startTransaction("Create type from C definition")
      try
        val dtm = program.getDataTypeManager()
        val parser = new ghidra.app.util.cparser.C.CParser(dtm)
        Option(parser.parse(cDefinition)) match
          case None => s"Failed to parse C definition: $cDefinition"
          case Some(parsedType) =>
            dtm.addDataType(parsedType, null)
            s"Successfully created type: ${parsedType.getName} (${parsedType.getClass.getSimpleName})"
      catch
        case e: ghidra.app.util.cparser.C.ParseException =>
          s"Parse error in C definition: ${e.getMessage}"
        case e: Exception =>
          s"Error creating type from C definition: ${e.getMessage}"
      finally program.endTransaction(tx, true)
    }.getOrElse("No program loaded")

  def exportFunctions(): String =
    context.withProgram { program =>
      val sb = new StringBuilder("Functions Export:\n")
      program.getFunctionManager().getFunctions(true).iterator().asScala.foreach { func =>
        sb.append(s"Function: ${func.getName} @ ${func.getEntryPoint}\n")
        sb.append(s"  Signature: ${func.getSignature}\n")
        sb.append(s"  Parameters: ${func.getParameterCount}\n\n")
      }
      sb.toString
    }.getOrElse("No program loaded")

  def exportData(addressStr: String, length: Int): String =
    context.withProgram { program =>
      parseAddress(program, addressStr).fold(
        err => s"Error: $err",
        addr =>
          if length <= 0 || length > 1024 * 1024 then
            s"Error: Invalid length (must be 1-1048576): $length"
          else try
            val bytes = new scala.Array[Byte](length)
            val bytesRead = program.getMemory().getBytes(addr, bytes)
            if bytesRead != length then s"Error: Could only read $bytesRead of $length bytes"
            else bytes.map(b => f"${b & 0xFF}%02x").mkString
          catch case e: Exception => s"Error: ${e.getMessage}"
      )
    }.getOrElse("Error: No program loaded")

  // Private Helpers (Pure Functions)
  // =================================

  private def streamFunctions(program: Program): Iterator[Function] =
    program.getFunctionManager().getFunctions(true).iterator().asScala

  private def findFunctionByName(program: Program, name: String): Either[String, Function] =
    streamFunctions(program).find(_.getName == name)
      .toRight(s"Function '$name' not found")

  private def findFunctionByAddress(program: Program, address: Address): Either[String, Function] =
    Option(program.getFunctionManager().getFunctionAt(address))
      .toRight(s"No function at address: $address")

  private def parseAddress(program: Program, addressStr: String): Either[String, Address] =
    try
      if addressStr == null || addressStr.trim.isEmpty then
        Left(s"Invalid address format: $addressStr")
      else
        Option(program.getAddressFactory().getAddress(addressStr.trim))
          .toRight(s"Invalid address format: $addressStr")
    catch case e: Exception =>
      Left(s"Invalid address format: $addressStr - ${e.getMessage}")

  private def decompileFunction(program: Program, function: Function): Either[String, String] =
    val decomp = new DecompInterface()
    decomp.openProgram(program)
    val results = decomp.decompileFunction(function, 30, context.getTaskMonitor())
    if results == null then Left("Decompilation returned null")
    else if !results.decompileCompleted() then Left("Decompilation failed")
    else
      try Right(results.getDecompiledFunction.getC)
      catch case e: Exception => Left(s"Error extracting decompiled C: ${e.getMessage}")

  private def tryRename(function: Function, newName: String): Boolean =
    try
      function.setName(newName, SourceType.USER_DEFINED)
      true
    catch case e: Exception =>
      context.showError(s"Failed to rename function: ${e.getMessage}")
      false

  private def disassembleFunctionInstructions(program: Program, function: Function): String =
    try
      val header = s"Function: ${function.getName} @ ${function.getEntryPoint}\n"
      val instructions = program.getListing().getInstructions(function.getBody, true).iterator().asScala
        .map(inst => s"${inst.getAddress}: $inst")
        .mkString("\n")
      header + instructions
    catch case e: Exception => s"Error disassembling function: ${e.getMessage}"

  private def getPrimarySymbolLabel(program: Program, address: Address): Either[String, String] =
    try
      Option(program.getSymbolTable().getPrimarySymbol(address))
        .flatMap(sym => Option(sym.getName).filter(_.trim.nonEmpty).map(escapeNonAscii))
        .map(Right(_))
        .getOrElse(Right(""))
    catch case e: Exception =>
      Left(s"Error resolving primary symbol label at $address: ${e.getMessage}")

  private def escapeNonAscii(input: String): String =
    if input == null then ""
    else input.map(c => if c >= 32 && c <= 126 then c.toString else f"\\x${c.toInt}%02x").mkString
