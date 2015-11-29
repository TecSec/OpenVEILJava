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

public class Session
{
	public native void release();
	public native void close();
	public native LoginStatus login(String pin);
	public native boolean getIsLoggedIn();
	public native boolean logout();
	//boolean GenerateWorkingKey(Asn1::CTS::CkmCombineParameters& params, std::function<bool(Asn1::CTS::CkmCombineParameters&, tsData&)> headerCallback, tsData &WorkingKey);
	//boolean RegenerateWorkingKey(Asn1::CTS::CkmCombineParameters& params, tsData &WorkingKey);
	public native String getProfile();
	public native boolean getIsLocked();
	public native int getRetriesLeft();
	public native boolean getIsValid();
	public native Session duplicate();
	public native boolean encryptFileUsingFavorite(Favorite fav, String sourceFile, boolean compress, String encryptedFile);
	public native boolean decryptFile(String encryptedFile, String decryptedFile);
	public native byte[] encryptDataUsingFavorite(Favorite fav, byte[] sourceData, boolean compress);
	public native byte[] decryptData(byte[] encryptedData);
	
	private native void initialize();
	public native void terminate();

	public Session()
	{
		initialize();
	}

	private long handle;

	//
	// Load DLL (or shared library) which contains implementation of native methods
	//
	static
	{
		System.loadLibrary("OpenVEILjavaWrapper");
	}
	
}
