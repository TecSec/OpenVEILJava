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
package com.tecsec.OpenVEIL;

public class KeyVEILConnector extends Connector
{
	public native ConnectionStatus connectToServer(String url, String username, String password);
	public native void disconnect();
	public native boolean isConnected();
	public native boolean sendJsonRequest(String verb, String cmd, String inData, RequestResults results);
	public native boolean sendBase64Request(String verb, String cmd, String inData, RequestResults results);
	public native boolean sendRequest(String verb, String cmd, byte[] inData, RequestResultsBinary results);

	public native boolean refresh();
	public native int tokenCount();
	public native Token tokenByIndex(int index);
	public native Token tokenByName(String tokenName);
	public native Token tokenBySerialNumber(byte[] serialNumber);
	public native Token tokenBySerialNumber(String serialNumber);
	public native Token tokenById(String id);
	public native int favoriteCount();
	public native Favorite favoriteByIndex(int index);
	public native Favorite favoriteByName(String name);
	public native Favorite favoriteById(String id);
	public native String CreateFavorite(Token token, byte[] headerData, String name);
	public native String CreateFavorite(String tokenId, byte[] headerData, String name);
	public native String CreateFavorite(byte[] tokenSerial, byte[] headerData, String name);
	public native boolean DeleteFavorite(String id);
	public native boolean UpdateFavoriteName(String id, String name);
	public native boolean UpdateFavorite(String id, byte[] setTo);
	public native int tokenCountForEnterpriseId(String enterpriseId);
	public native Token tokenForEnterprise(String enterpriseId, int index);
	public native int favoriteCountForEnterprise(String enterpriseId);
	public native Favorite favoriteForEnterprise(String enterpriseId, int index);
	
	private native void initialize();
	public native void terminate();

	public KeyVEILConnector()
	{
		initialize();
	}
	//
	// Load DLL (or shared library) which contains implementation of native methods
	//
	static
	{
		System.loadLibrary("OpenVEILjavaWrapper");
	}
	
}
