package systems.dmx.ldap;

import java.util.logging.Level;
import java.util.logging.Logger;

interface PluginLog {

	void configurationDebug(String msg, Object... args);
	
	void configurationHint(String msg, Object... args);
	
	void configurationWarning(String msg, Object... args);
	
	void configurationError(String msg, Object... args);

	void actionHint(String msg, Object... args);

	void actionWarning(String message, Throwable throwable);
	
	void actionError(String message, Throwable throwable);

	static PluginLog newInstance(Configuration.LoggingMode lm) {
		switch (lm) {
			default:
			case INFO:
				return new ProductionLog();
			case DEBUG:
				return new TroubleShootingLog();
		}
	}
	
}

class ProductionLog implements PluginLog {
	
	Logger logger = Logger.getLogger(ProductionLog.class.getName());

	@Override
	public void configurationDebug(String msg, Object... args) {
		// Debug messages are disabled in production log
	}

	@Override
	public void configurationHint(String msg, Object... args) {
		// Hints are disabled in production log
	}

	@Override
	public void configurationWarning(String msg, Object... args) {
		logger.log(Level.WARNING, String.format(msg, args));
	}

	@Override
	public void configurationError(String msg, Object... args) {
		logger.log(Level.SEVERE, String.format(msg, args));
	}
	
    @Override
    public void actionHint(String msg, Object... args) {
		// Hints are disabled in production log
    }
    
    @Override
    public void actionWarning(String message, Throwable throwable) {
		logger.log(Level.WARNING, message, throwable);
    }

    @Override
    public void actionError(String message, Throwable throwable) {
		logger.log(Level.SEVERE, message, throwable);
    }

}
