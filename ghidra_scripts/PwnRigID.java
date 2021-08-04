//Identify build name 
//@author Lacework Labs
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;

public class PwnRig_ID extends GhidraScript {
	
	static String built_date = "\n built on"; //PwnRig build string.
	
	@Override
	protected void run() throws Exception {
		println("=====================================================\n");
		println("Triaging " + getCurrentProgram().getName().toString());
		analyzeAll(this.currentProgram); // initially analyze so we can xref strings.
		findConfigs();
		println("=====================================================\n");
	}
	
	
	boolean findConfigs() throws Exception {
		Address Args = find(built_date); 

		if (Args == null) {
			println("[!] Could not find cli_args hardcoded string");
			return false;
		}
		
		// loop through references to build_date string
		Reference[] refs = getReferencesTo(Args);
		for (Reference ref : refs) {

			createLabel(ref.getFromAddress(), "build_date", false); // creaing a label within the Ghidra project
			println("PwnRig Name & XMRig Args: " + getFunctionContaining(ref.getFromAddress()).toString());
			println("Build info: " + getDataAt(ref.getToAddress()).toString());
			break;
			
		}
		return true;
	}

}
