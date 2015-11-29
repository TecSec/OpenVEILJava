//	Copyright (c) 2015, TecSec, Inc.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	
//		* Redistributions of source code must retain the above copyright
//		  notice, this list of conditions and the following disclaimer.
//		* Redistributions in binary form must reproduce the above copyright
//		  notice, this list of conditions and the following disclaimer in the
//		  documentation and/or other materials provided with the distribution.
//		* Neither the name of TecSec nor the names of the contributors may be
//		  used to endorse or promote products derived from this software 
//		  without specific prior written permission.
//		 
//	ALTERNATIVELY, provided that this notice is retained in full, this product
//	may be distributed under the terms of the GNU General Public License (GPL),
//	in which case the provisions of the GPL apply INSTEAD OF those given above.
//		 
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
/*
 * put this in a file named CommandLineExample.java
 *
 */

 import com.tecsec.OpenVEIL.*;
 
class tokenList
{
	public static String toHexString(byte[] bytes) {
		char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
		char[] hexChars = new char[bytes.length * 2];
		int v;
		for ( int j = 0; j < bytes.length; j++ ) {
			v = bytes[j] & 0xFF;
			hexChars[j*2] = hexArray[v/16];
			hexChars[j*2 + 1] = hexArray[v%16];
		}
		return new String(hexChars);
	}
	private static final byte[] inData = new byte[] { 1, 2, 3, 4, 5 };

    public static void main ( String [] arguments )
    {
		Environment env = new Environment();
		
		try
		{
			env.InitializeVEIL(false);
		
			KeyVEILConnector kvConn = new KeyVEILConnector();
			kvConn.connectToServer("http://localhost:8125", "user1", "11111111");
			
			for (int i = 0; i < kvConn.tokenCount(); i++)
			{
				Token token = kvConn.tokenByIndex(i);
				System.out.println("");
				System.out.println("Token");
				System.out.println("  Name:            " + token.getTokenName());
				System.out.println("  Type:            " + token.getTokenType());
				System.out.println("  serialNumber:    " + toHexString(token.getSerialNumber()));
				System.out.println("  id:              " + token.getId());
				System.out.println("  Enterprise name: " + token.getEnterpriseName());
				System.out.println("  Enterprise ID:   " + token.getEnterpriseId());
				System.out.println("  Member Name:     " + token.getMemberName());
				System.out.println("  Member ID:       " + token.getMemberId());
			}
			for (int i = 0; i < kvConn.favoriteCount(); i++)
			{
				Favorite fav = kvConn.favoriteByIndex(i);

				System.out.println("");
				System.out.println("Favorite");
				System.out.println("  Name:         " + fav.getFavoriteName());
				System.out.println("  ID:           " + fav.getFavoriteId());
				System.out.println("  Enterprise:   " + fav.getEnterpriseId());
				System.out.println("  Token Serial: " + toHexString(fav.getTokenSerialNumber()));
			}
		
			Session session = kvConn.tokenBySerialNumber("906845AEC554109D").openSession();
			
			System.out.println("SESSION");
			System.out.println("Is Valid:      " + session.getIsValid());
			System.out.println("Is logged in:  " + session.getIsLoggedIn());

			if (!session.getIsLoggedIn())
			{
				System.out.println("  login returned:  " + session.login("11111111"));
				System.out.println("  Is logged in:    " + session.getIsLoggedIn());
			}
			
			System.out.println("Original data: " + toHexString(inData));

			byte[] outData = kvConn.favoriteByName("Staff").encryptData(session, inData, true);

			System.out.println("Encrypted data: " + toHexString(outData));

			byte[] newSrc = session.decryptData(outData);

			System.out.println("Decrypted data: " + toHexString(newSrc));
	
			//	
			// Now try file encryption using the same encryption information
			//
			System.out.println("File encrypt returned " + kvConn.favoriteByName("Staff").encryptFile(session, "tokenList.jar", true, "tokenList.jar.ckm"));
			System.out.println("File decrypt returned " + session.decryptFile("tokenList.jar.ckm", "tokenList.jar2"));

		}
		finally
		{
			env.TerminateVEIL();
		}
    }
	static
	{
		System.loadLibrary("OpenVEILjavaWrapper");
	}
}

/*

*/