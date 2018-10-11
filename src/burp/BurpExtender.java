package burp;

public class BurpExtender implements IBurpExtender, IProxyListener {
	
	
	private static final String[] HOSTS_FROM = {"google.com", "facebook.com"};
	
	private IExtensionHelpers helpers;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		helpers = callbacks.getHelpers();
		
		callbacks.setExtensionName("Request Filter");
		callbacks.registerProxyListener(this);
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		if (messageIsRequest) {
			IHttpRequestResponse messageInfo = message.getMessageInfo();
			IHttpService httpService = messageInfo.getHttpService();
			for (String s : HOSTS_FROM) {
				if (httpService.getHost().toLowerCase().contains(s)) {
					message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
				}
			}
		}
	}
	

}
