// Dump the symbols and comments applied from the WebAssembly `.name` section, for spot-checking
// the WasmNameApplyAnalyzer. Every line is prefixed "NAMES " so the output is easy to grep.
//@category Test

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;

public class DumpNames extends GhidraScript {

	@Override
	public void run() throws Exception {
		println("NAMES program=" + currentProgram.getName());
		Listing listing = currentProgram.getListing();

		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			println("NAMES BLOCK " + block.getName() + " @ " + block.getStart() +
				" size=" + block.getSize());
			String comment = listing.getComment(CommentType.PLATE, block.getStart());
			if (comment != null && !comment.isEmpty()) {
				println("NAMES BLOCK-COMMENT " + block.getName() + " @ " + block.getStart() +
					" :: " + comment.replace("\n", " | "));
			}
		}

		for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
			String comment = listing.getComment(CommentType.PLATE, function.getEntryPoint());
			if (comment != null && !comment.isEmpty()) {
				println("NAMES FUNC-COMMENT " + function.getName() + " @ " +
					function.getEntryPoint() + " :: " + comment.replace("\n", " | "));
			}
		}

		for (Symbol symbol : currentProgram.getSymbolTable().getAllSymbols(true)) {
			if (symbol.isDynamic()) {
				continue;
			}
			println("NAMES SYMBOL " + symbol.getName() + " @ " + symbol.getAddress() +
				" source=" + symbol.getSource() +
				" ns=" + symbol.getParentNamespace().getName());
		}
	}
}
