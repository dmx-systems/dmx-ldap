package de.deepamehta.ldap;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingException;

public class TroubleShootingLog implements PluginLog {

	private Logger logger = Logger.getLogger(TroubleShootingLog.class.getName());
	
	@Override
	public void configurationHint(String msg, Object... args) {
		logger.log(Level.INFO, String.format(msg, args));
	}

	@Override
	public void configurationWarning(String msg, Object... args) {
		logger.log(Level.WARNING, String.format(msg, args));
	}

	@Override
	public void configurationError(String msg, Object... args) {
		logger.log(Level.SEVERE, String.format(msg, args));
	}
	
	private static String prepareMessage(String message, Throwable throwable) {
    	StringBuffer sb = new StringBuffer();
    	sb.append(message);
    	
    	if (throwable != null) {
        	sb.append(": ");
        	appendMessage(sb, throwable);
    	}
    	
    	return sb.toString();
	}

    private static void appendMessage(StringBuffer sb, Throwable throwable) {
    	sb.append(throwable.getLocalizedMessage());
    	
    	if (throwable instanceof NamingException) {
        	sb.append(": ");
        	sb.append(((NamingException) throwable).getExplanation());
    	}
    	
    	Throwable parent = throwable.getCause();
    	if (parent != null) {
    		sb.append(" caused by ");
    		appendMessage(sb, parent);
    	}
    }
    
    @Override
    public void actionHint(String msg, Object... args) {
		logger.log(Level.INFO, String.format(msg, args));
    }
    
    @Override
    public void actionWarning(String message, Throwable throwable) {
    	logger.log(Level.WARNING, prepareMessage(message, throwable));
    }

    @Override
    public void actionError(String message, Throwable throwable) {
    	logger.log(Level.SEVERE, prepareMessage(message, throwable));
    }

}
