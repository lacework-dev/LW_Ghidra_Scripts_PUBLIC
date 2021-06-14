//Identify configuration from within Katien/Tsunami/Ziggystratux variants
//@author Lacework Labs
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;

public class PwnKatien extends GhidraScript {
	
	static String nick_user = "NICK %s\nUSER %s localhost localhost :%s\n";

	static int off_channel = 72;
	static int off_key = 58;
	static int off_botname = 280;


	@Override
	protected void run() throws Exception {
		println("=====================================================");
		println("Triaging " + getCurrentProgram().getName().toString());
		analyzeAll(this.currentProgram); // Initially analyze so we can xref strings.
		findConfigs();
		println("=====================================================");
	}
	
	/**
	 *  Identify configuration section based on references to the nick user string.
	 * @return true if configuration information is found, false if configuration information is not found.
	 * @throws Exception
	 */
	boolean findConfigs() throws Exception {

		Address Nickaddr = find(getMemoryBlock(".rodata").getStart(), nick_user.getBytes()); // find NICK reg string in .rodata section

		if (Nickaddr == null) {
			println("Could not find IRC Nick registration.");
			return false;
		}
		
		Reference[] refs = getReferencesTo(Nickaddr); // find refs to Nickuser string.
		
		if (refs.length > 1) {
			println("[!] There's more than one reference to \"" + nick_user.replace("\n", "") + "\"... this is unusual.");
		}


		/* for each reference that's hit identify config section. Different variants of this bot may 
		 * have xrefs to various sections and then this data is the same. 
		 * To avoid printing duplicate data, uncomment the break within the
		 * reference loop.
		*/
		for (Reference ref : refs) {

			Address config = ref.getFromAddress().subtract(86); // rough offset to config section

			// Main was not identified, will label (if the binary is stripped this helps)
			if (!getSymbolBefore(config).toString().equals("main")) { 
				Address new_main = getSymbolBefore(config).getAddress();
				println("[*] I think main is at " + new_main + " creating new label for ya!");
				createLabel(new_main, "main", true);
			}
			
			// print all configuration data to console. Click on the addresses to jump to them in Ghidra.
			println("(main - config section) Channel: " + ref.getFromAddress().subtract(off_channel+7)); 
			println("(main - config section) Key: " + ref.getFromAddress().subtract(off_key));
			println("(main - config section) process name: " + ref.getFromAddress().subtract(off_botname));

			println("(RO Section) IPv4s/Domains should be at or around: " + getMemoryBlock(".rodata").getStart().toString());
			println("(RO Section) password at: " + ref.getToAddress().subtract(4)); 
			println("(RO Section) channel at: " + ref.getToAddress().subtract(8));
			println("(RO Section) process name at: " + ref.getToAddress().subtract(12));

			// break; // uncomment this to avoid duplicant prints.
		}
		return true;
	}
}
