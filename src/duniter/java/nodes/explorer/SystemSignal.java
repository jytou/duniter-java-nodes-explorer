package duniter.java.nodes.explorer;

import java.awt.AWTException;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.SystemTray;
import java.awt.Toolkit;
import java.awt.TrayIcon;
import java.awt.TrayIcon.MessageType;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class SystemSignal
{
	private TrayIcon mTrayIcon;

	private static Image getTrayIconImage()
	{
		return Toolkit.getDefaultToolkit().getImage(SystemSignal.class.getResource("duniter-logo24.png"));
	}

	private static BufferedImage scale(Image imageToScale, int dWidth, int dHeight, Color pBackground)
	{
        BufferedImage scaledImage = null;
        if (imageToScale != null)
        {
            scaledImage = new BufferedImage(dWidth, dHeight, BufferedImage.TYPE_INT_ARGB);
            Graphics2D graphics2D = scaledImage.createGraphics();
            graphics2D.setColor(pBackground);
            graphics2D.fillRect(0, 0, dWidth, dHeight);
            graphics2D.drawImage(imageToScale, 0, 0, dWidth, dHeight, null);
            graphics2D.dispose();
        }
        return scaledImage;
    }

	public SystemSignal()
	{
		super();
		mTrayIcon = null;
		if (new File("/usr/bin/notify-send").exists())
		{
			mTrayIcon = new TrayIcon(getTrayIconImage())
			{
				@Override
				public void displayMessage(String pCaption, String pText, MessageType pMessageType)
				{
					try
					{
						new ProcessBuilder(Arrays.asList(new String[] {"/usr/bin/notify-send", "-c", pCaption, pText})).start();
					}
					catch (IOException e1)
					{
						e1.printStackTrace();// should never happen
					}
				}
			};
			if (SystemTray.isSupported())
				try
				{
					SystemTray.getSystemTray().add(mTrayIcon);
				}
				catch (AWTException e)
				{
					e.printStackTrace();
				}
		}
		else if (SystemTray.isSupported())
			try
			{
				mTrayIcon = new TrayIcon(getTrayIconImage());
				SystemTray.getSystemTray().add(mTrayIcon);
			}
			catch (AWTException e1)
			{
				e1.printStackTrace();
			}
	}

	public void health(Color pTrayColor)
	{
		if (mTrayIcon != null)
			mTrayIcon.setImage(scale(getTrayIconImage(), 24, 24, pTrayColor));
	}

	public void displayWarning(String pTitle, String pMessage)
	{
		if (mTrayIcon != null)
			mTrayIcon.displayMessage(pTitle, pMessage, MessageType.WARNING);
	}
}
