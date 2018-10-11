package burp;

public class BurpExtender implements IBurpExtender, IHttpListener {
	
	private static final String[] HOSTS_FROM = {"google.com", "facebook.com"};
	
	private IExtensionHelpers helpers;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		helpers = callbacks.getHelpers();
		
		callbacks.setExtensionName("Request Filter");
		callbacks.registerHttpListener(this);
	}
	
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageIsRequest) {
			IHttpService httpService = messageInfo.getHttpService();
			for (String s : HOSTS_FROM) {
				if (httpService.getHost().toLowerCase().contains(s)) {
					messageInfo.setHttpService(helpers.buildHttpService(null, httpService.getPort(), httpService.getProtocol()));
				}
			}
		}
	}
	

}
