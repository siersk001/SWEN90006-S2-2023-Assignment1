package swen90006.mfa;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.file.FileSystems;

import org.junit.*;
import static org.junit.Assert.*;

//By extending PartitioningTests, we inherit the tests from that class
public class BoundaryTests
    extends PartitioningTests
{
    //Add another test
    @Test public void anotherTest()
    {
	//include a message for better feedback
	final int expected = 2;
	final int actual = 2;
	assertEquals("Some failure message", expected, actual);
    }

    /*
     * reister boundary value analysis
     */
    @Test(expected = DuplicateUserException.class)
    public void register_BV1() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        mfa.register(username, password, deviceID, faceid);
        assertTrue(mfa.isUser(username));
    }

    @Test(expected = InvalidUsernameException.class)
    public void register_BV2() throws Throwable{
        String username = "abc";
        String password = "123abcd~";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        assertFalse(mfa.isUser(username));
    }

    @Test(expected = InvalidPasswordException.class)
    public void register_BV3() throws Throwable{
        String username = "abcd";
        String password = "123abc~";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
    }

    @Test(expected = InvalidUsernameException.class)
    public void register_BV4() throws Throwable{
        String username = "~abc";
        String password = "123abcd~";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        assertFalse(mfa.isUser(username));
    }

    @Test(expected = InvalidPasswordException.class)
    public void register_BV5() throws Throwable{
        String username = "abcd";
        String password = "1234567~";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
    }

    @Test(expected = InvalidPasswordException.class)
    public void register_BV6() throws Throwable{
        String username = "abcd";
        String password = "~!@#$^&";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
    }

    @Test(expected = InvalidPasswordException.class)
    public void register_BV7() throws Throwable{
        String username = "abcd";
        String password = "1234abcd";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
    }

    @Test
    public void register_BV8() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        assertTrue(mfa.isUser(username));
    }

    @Test
    public void register_BV9() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceID = "equipment";
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        assertTrue(mfa.isUser(username));
    }

    @Test
    public void register_BV10() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceID = "equipment";
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        assertTrue(mfa.isUser(username));
    }

    @Test
    public void register_BV11() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceID = "equipment";
        String faceid = "handsomeFace";
        mfa.register(username, password, deviceID, faceid);
        assertTrue(mfa.isUser(username));
    }

    /*
     * login boundary value analysis
     */

     @Test(expected = NoSuchUserException.class)
     public void login_BV1() throws Throwable{
         String username = "abcc";
         String password = "123abcd~";
         String deviceId = null;
         String faceId = null;
         MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
         assertEquals(MFA.AuthenticationStatus.NONE, status);
     }
 
     @Test(expected = IncorrectPasswordException.class)
     public void login_BV2() throws Throwable{
         String username = "abcd";
         String password = "123abcd~~";
         String deviceId = null;
         String faceId = null;
         MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
         assertEquals(MFA.AuthenticationStatus.NONE, status);
     }
 
     @Test
     public void login_BV3() throws Throwable{
         String username = "abcd";
         String password = "123abcd~";
         String deviceId = null;
         String faceId = null;
         MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
         assertEquals(MFA.AuthenticationStatus.SINGLE, status);
     }
 
     @Test(expected = IncorrectDeviceIDException.class)
     public void login_BV4() throws Throwable{
         String username = "abcd";
         String password = "123abcd~";
         String deviceId = "device";
         String faceId = null;
         MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
         assertEquals(MFA.AuthenticationStatus.DOUBLE, status);
     }
 
     @Test
     public void login_BV5() throws Throwable{
         String username = "abcd";
         String password = "123abcd~";
         String deviceId = "equipment";
         String faceId = null;
         MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
         assertEquals(MFA.AuthenticationStatus.DOUBLE, status);
     }
 
     @Test(expected = FaceMismatchException.class)
     public void login_BV6() throws Throwable{
         String username = "abcd";
         String password = "123abcd~";
         String deviceId = "equipment";
         String faceId = "face";
         MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
         assertEquals(MFA.AuthenticationStatus.TRIPLE, status);
     }
 
     @Test
     public void login_BV7() throws Throwable{
         String username = "abcd";
         String password = "123abcd~";
         String deviceId = "equipment";
         String faceId = "face";
         MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
         assertEquals(MFA.AuthenticationStatus.NONE, status);
     }
 
     @Test
     public void login_BV8() throws Throwable{
         String username = "abcd";
         String password = "123abcd~";
         String deviceId = "equipment";
         String faceId = "handsomeFace";
         MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
         assertEquals(MFA.AuthenticationStatus.TRIPLE, status);
     }

     /*
     * respondToPushNotification boundary value analysis
     */
    @Test(expected = NoSuchUserException.class)
    public void respondToPushNotification_BV1() throws Throwable{
        String username = "abcc";
        String deviceID = "device";
        mfa.respondToPushNotification(username,deviceID);
    }

    @Test(expected = NoSuchUserException.class)
    public void respondToPushNotification_BV2() throws Throwable{
        String username = "abcd";
        String deviceID = "";
        MFA.AuthenticationStatus status = mfa.respondToPushNotification(username,deviceID);
        assertEquals(MFA.AuthenticationStatus.NONE, status);
        
    }

    @Test(expected = IncorrectDeviceIDException.class)
    public void respondToPushNotification_BV3() throws Throwable{
        String username = "abcd";
        String deviceID = "device";
        MFA.AuthenticationStatus status = mfa.respondToPushNotification(username,deviceID);
        assertEquals(MFA.AuthenticationStatus.SINGLE, status);
        
    }
    
    @Test
    public void respondToPushNotification_BV4() throws Throwable{
        String username = "abcd";
        String deviceID = "equipment";
        MFA.AuthenticationStatus status = mfa.respondToPushNotification(username,deviceID);
        assertEquals(MFA.AuthenticationStatus.DOUBLE, status);
        
    }

     /*
     * faceRecognised boundary value analysis
     */

     @Test(expected = NoSuchUserException.class)
     public void faceRegonised_BV1() throws Throwable{
         String username = "abcc";
         String deviceID = "device";
         String facialId = "face";
         mfa.faceRegonised(username,deviceID,facialId);
     }
 
     @Test
     public void faceRegonised_BV2() throws Throwable{
         String username = "abcd";
         String deviceID = "";
         String facialId = "";
         MFA.AuthenticationStatus status = mfa.faceRegonised(username,deviceID,facialId);
         assertEquals(MFA.AuthenticationStatus.NONE, status);
     }
     
     @Test(expected = IncorrectDeviceIDException.class)
     public void faceRegonised_BV3() throws Throwable{
         String username = "abcd";
         String deviceID = "device";
         String facialId = "";
         MFA.AuthenticationStatus status = mfa.faceRegonised(username,deviceID,facialId);
         assertEquals(MFA.AuthenticationStatus.SINGLE, status);
     }
 
     @Test(expected = IncorrectDeviceIDException.class)
     public void faceRegonised_BV4() throws Throwable{
         String username = "abcd";
         String deviceID = "equipment";
         String facialId = "";
         MFA.AuthenticationStatus status = mfa.faceRegonised(username,deviceID,facialId);
         assertEquals(MFA.AuthenticationStatus.SINGLE, status);
     }
 
     @Test(expected = FaceMismatchException.class)
     public void faceRegonised_BV5() throws Throwable{
         String username = "abcd";
         String deviceID = "equipment";
         String facialId = "face";
         MFA.AuthenticationStatus status = mfa.faceRegonised(username,deviceID,facialId);
         assertEquals(MFA.AuthenticationStatus.DOUBLE, status);
     }
 
     @Test
     public void faceRegonised_BV6() throws Throwable{
         String username = "abcd";
         String deviceID = "equipment";
         String facialId = "handsomeFace";
         MFA.AuthenticationStatus status = mfa.faceRegonised(username,deviceID,facialId);
         assertEquals(MFA.AuthenticationStatus.TRIPLE, status);
     }

     /*
     * getData boundary value analysis
     */

    @Test(expected = NoSuchUserException.class)
    public void getData_BV1() throws Throwable{
        String username = "abcc";
        Integer index = 0;
        mfa.getData(username,index);
        
    }

    @Test(expected = UnauthenticatedUserException.class)
    public void getData_BV2() throws Throwable{
        String username = "abcd";
        Integer index = -1;
        mfa.getData(username,index);
        assertFalse(mfa.isAuthenticated(username));
    }

    @Test
    public void getData_BV3() throws Throwable{
        String username = "aaaa";
        Integer index = -1;
        List<Integer> data = Arrays.asList(1,2,3,4,5);
        mfa.register(username, "1234abc~", null,null);
        mfa.login(username, "1234abc~");
        mfa.addData(username, data);
        mfa.getData(username,index);
    }

    @Test
    public void getData_BV4_1() throws Throwable{
        String username = "aaaa";
        Integer index = 0;
        List<Integer> data = Arrays.asList(1,2,3,4,5);
        mfa.register(username, "1234abc~", null,null);
        mfa.login(username, "1234abc~");
        mfa.addData(username, data);
        List<Integer> datas = mfa.getData(username,index);
        assertEquals(data, datas);
    }

     @Test
    public void getData_BV4_2() throws Throwable{
        String username = "aaaa";
        Integer index = 4;
        List<Integer> data = Arrays.asList(1,2,3,4,5);
        mfa.register(username, "1234abc~", null,null);
        mfa.login(username, "1234abc~");
        mfa.addData(username, data);
        List<Integer> datas = mfa.getData(username,index);
        assertEquals(data, datas);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void getData_BV5() throws Throwable{
        String username = "aaaa";
        Integer index = 5;
        List<Integer> data = Arrays.asList(1,2,3,4,5);
        mfa.register(username, "1234abc~", null,null);
        mfa.login(username, "1234abc~");
        mfa.addData(username, data);
        mfa.getData(username,index);
    }
}
