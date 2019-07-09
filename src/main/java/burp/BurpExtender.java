package burp;

import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import net.razorvine.pyro.PyroProxy;
import net.razorvine.pyro.PyroURI;
import net.razorvine.pickle.PrettyPrint;

public class BurpExtender implements IBurpExtender, IHttpListener {
  private PrintWriter stdout;
  private PrintWriter stderr;	    
  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;
    
  public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
    // Set the name of the extension
    callbacks.setExtensionName("Brida Custom Plugin");		
    // Initialize stdout and stderr (configurable from the Extension pane)
    stdout = new PrintWriter(callbacks.getStdout(), true);
    stderr = new PrintWriter(callbacks.getStderr(), true);  
    // Save references to useful objects
    this.callbacks = callbacks;
    this.helpers = callbacks.getHelpers();
    // Register ourselves as an HttpListener, in this way all requests and responses will be forwarded to us
    callbacks.registerHttpListener(this);
  }

  public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    
    // Process only Repeater, Scanner and Intruder requests
    if(toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER || 
       toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER ||		
       toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER) {
      
      // Modify "test" parameter of Repeater requests			
      if(messageIsRequest) {
        // Get request bytes
        byte[] request = messageInfo.getRequest();
        // Get a IRequestInfo object, useful to work with the request
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        // Get the headers
        List<String> headers = requestInfo.getHeaders();
        // Get "test" parameter
        //IParameter contentParameter = helpers.getRequestParameter(request, "content");
        // Get body
        String requestStr = new String(request);
        byte[] body = requestStr.substring(requestInfo.getBodyOffset()).getBytes();
        if(body != null) {
          //String urlDecodedContentParameterValue = helpers.urlDecode(contentParameter.getValue());
          String ret = "";
          // Ask Brida to encrypt our attack vector
          String pyroUrl = "PYRO:BridaServicePyro@localhost:9999";
          try {
            PyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));
            Object retObj = pp.call("callexportfunction","encrypt",new String[]{helpers.bytesToString(body)});
            ret = PrettyPrint.printToStr(retObj);
            pp.close();
          } catch(Exception e) {
            stderr.println(e.toString());
            StackTraceElement[] exceptionElements = e.getStackTrace();
            for(int i=0; i< exceptionElements.length; i++) {
              stderr.println(exceptionElements[i].toString());
            }							
          }
          // Create the new parameter
          //IParameter newTestParameter = helpers.buildParameter(contentParameter.getName(), helpers.urlEncode(ret), contentParameter.getType());
          // Create the new request with the updated parameter
          //byte[] newRequest = helpers.updateParameter(request, newTestParameter);
          
          byte[] newRequest = helpers.buildHttpMessage(headers, helpers.stringToBytes(ret)); //
          
          // Update the messageInfo object with the modified request (otherwise the request remains the old one)
          
          messageInfo.setRequest(newRequest);
        }				
      
      // Response
      } else {
    	// Get request bytes
          byte[] request = messageInfo.getRequest();
          // Get a IRequestInfo object, useful to work with the request
          IRequestInfo requestInfo = helpers.analyzeRequest(request);
          // Get "test" parameter
          //IParameter contentParameter = helpers.getRequestParameter(request, "content");
          // Get body
          String requestStr = new String(request);
          byte[] reqbody = requestStr.substring(requestInfo.getBodyOffset()).getBytes();
        if(reqbody != null) {
          // Get response bytes
          byte[] response = messageInfo.getResponse();
          // Get a IResponseInfo object, useful to work with the request
          IResponseInfo responseInfo = helpers.analyzeResponse(response);
          // Get the offset of the body
          int bodyOffset = responseInfo.getBodyOffset();
          // Get the body (byte array and String)
          byte[] body = Arrays.copyOfRange(response, bodyOffset, response.length);
          String bodyString = helpers.bytesToString(body);
          String ret = "";
          // Ask Brida to decrypt the response
          String pyroUrl = "PYRO:BridaServicePyro@localhost:9999";
          try {
            PyroProxy pp = new PyroProxy(new PyroURI(pyroUrl));
            Object retObj = pp.call("callexportfunction","decrypt",new String[]{bodyString});
            String retStr = PrettyPrint.printToStr(retObj);
            String hexString = new String(retStr.getBytes(), "UTF-8");
            byte[] bytes = Hex.decodeHex(hexString.toCharArray());
            stderr.println(new String(bytes, "UTF-8"));
            
            //byte [] retb2 = retb.getBytes();
            ret = new String(bytes, "UTF-8");
            stderr.println(ret);
            pp.close();
          } catch(Exception e) {
            stderr.println(e.toString());
            StackTraceElement[] exceptionElements = e.getStackTrace();
            for(int i=0; i< exceptionElements.length; i++) {
              stderr.println(exceptionElements[i].toString());
            }							
          }
          // Update the messageInfo object with the modified request (otherwise the request remains the old one)
          byte[] newResponse = ArrayUtils.addAll(Arrays.copyOfRange(response, 0, bodyOffset),ret.getBytes());
          messageInfo.setResponse(newResponse);
        }
      }
    }
  }
  
  public static void main() throws Exception {
	  String hexString = "7b2272657475726e436f6465223a2239393939222c2272657475726e446573223a22e6898be69cbae58fb7e4b88de59088e6b395222c226170704964223a223861383861383066363562326534623830313635623265373633336230303030222c226465766963654964223a2237613766616265302d613734662d333865302d626139322d383763353130393539353030222c226d73674964223a22323031393037303931343039303434393738373838222c227369676e223a223835374230304241333437343436413646303742464241363833393837423236222c22656e636f64654d6574686f64223a22646573222c227369676e4d6574686f64223a227369676e222c22626f6479223a226e756c6c227d";    
	  byte[] bytes = Hex.decodeHex(hexString.toCharArray());
	  System.out.println(new String(bytes, "UTF-8"));
  }
}