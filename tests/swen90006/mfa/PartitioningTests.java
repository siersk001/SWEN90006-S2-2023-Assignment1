package swen90006.mfa;

import org.junit.*;
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PartitioningTests
{
    //mfa is a standard instance variable in Java. It is available to all test methods
    protected MFA mfa;

    //Any method annotated with "@Before" will be executed before each test,
    //allowing the tester to set up some shared resources.
    @Before public void setUp()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
        //Initialise the MFA instance and create a dummy user. This will run before each test
	mfa = new MFA();
	mfa.register("UserNameA", "Password1!", "", "");
    mfa.register("abcd", "1223abcd~", "equipment", "handsomeFace");
    }

    //Any method annotated with "@After" will be executed after each test,
    //allowing the tester to release any shared resources used in the setup.
    @After public void tearDown()
    {
    }

    //Any method annotation with "@Test" is executed as a test.
    @Test public void aTest()
    {
	//the assertEquals method used to check whether two values are
	//equal, using the equals method
	final int expected = 2;
	final int actual = 1 + 1;
	assertEquals(expected, actual);
    }

    @Test public void anotherTest()
	throws DuplicateUserException, InvalidUsernameException, InvalidPasswordException
    {
	mfa.register("UserNameB", "Password2!", "", "");

	//the assertTrue method is used to check whether something holds.
	assertTrue(mfa.isUser("UserNameB"));
	assertFalse(mfa.isUser("NonUser"));
    }

    //To test that an exception is correctly throw, specify the expected exception after the @Test
    @Test(expected = java.io.IOException.class)
    public void anExceptionTest()
	throws Throwable
    {
	throw new java.io.IOException();
    }

    //This test should fail.
    //To provide additional feedback when a test fails, an error message
    //can be included
    @Test public void aFailedTest()
    {
	//include a message for better feedback
	final int expected = 2;
	final int actual = 1 + 2;
	//Uncomment the following line to make the test fail
	//assertEquals("Some failure message", expected, actual);
    }

    /*
     * reister equivalence partitioning
     */
    @Test(expected = DuplicateUserException.class)
    public void register_EC1() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        assertTrue(mfa.isUser(username));
    }

    @Test(expected = InvalidUsernameException.class)
    public void register_EC2() throws Throwable{
        String username = "abc";
        String password = "123abcd~";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        assertFalse(mfa.isUser(username));
    }

    @Test(expected = InvalidPasswordException.class)
    public void register_EC3() throws Throwable{
        String username = "abcd";
        String password = "123abc~";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
    }

    @Test(expected = InvalidUsernameException.class)
    public void register_EC4() throws Throwable{
        String username = "~abc";
        String password = "123abcd~";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        assertFalse(mfa.isUser(username));
    }

    @Test(expected = InvalidPasswordException.class)
    public void register_EC5() throws Throwable{
        String username = "abcd";
        String password = "12345678";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
    }

    @Test(expected = InvalidPasswordException.class)
    public void register_EC6() throws Throwable{
        String username = "abcd";
        String password = "abcdefgh";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
    }

    @Test(expected = InvalidPasswordException.class)
    public void register_EC7() throws Throwable{
        String username = "abcd";
        String password = "1234abcd";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
    }

    @Test
    public void register_EC8() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceID = null;
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        assertTrue(mfa.isUser(username));
    }

    @Test
    public void register_EC9() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceID = "equipment";
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        assertTrue(mfa.isUser(username));
    }

    @Test
    public void register_EC10() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceID = "equipment";
        String faceid = null;
        mfa.register(username, password, deviceID, faceid);
        assertTrue(mfa.isUser(username));
    }

    @Test
    public void register_EC11() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceID = "equipment";
        String faceid = "handsomeFace";
        mfa.register(username, password, deviceID, faceid);
        assertTrue(mfa.isUser(username));
    }

    /*
     * login equivalencee partitioning
     */
    @Test(expected = NoSuchUserException.class)
    public void login_EC1() throws Throwable{
        String username = "abcc";
        String password = "123abcd~";
        String deviceId = null;
        String faceId = null;
        MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
        assertEquals(MFA.AuthenticationStatus.NONE, status);
    }

    @Test(expected = IncorrectPasswordException.class)
    public void login_EC2() throws Throwable{
        String username = "abcd";
        String password = "123abcd~~";
        String deviceId = null;
        String faceId = null;
        MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
        assertEquals(MFA.AuthenticationStatus.NONE, status);
    }

    @Test
    public void login_EC3() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceId = null;
        String faceId = null;
        MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
        assertEquals(MFA.AuthenticationStatus.SINGLE, status);
    }

    @Test(expected = IncorrectDeviceIDException.class)
    public void login_EC4() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceId = "device";
        String faceId = null;
        MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
        assertEquals(MFA.AuthenticationStatus.DOUBLE, status);
    }

    @Test
    public void login_EC5() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceId = "equipment";
        String faceId = null;
        MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
        assertEquals(MFA.AuthenticationStatus.DOUBLE, status);
    }

    @Test(expected = FaceMismatchException.class)
    public void login_EC6() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceId = "equipment";
        String faceId = "face";
        MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
        assertEquals(MFA.AuthenticationStatus.TRIPLE, status);
    }

    @Test
    public void login_EC7() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceId = "equipment";
        String faceId = "face";
        MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
        assertEquals(MFA.AuthenticationStatus.NONE, status);
    }

    @Test
    public void login_EC8() throws Throwable{
        String username = "abcd";
        String password = "123abcd~";
        String deviceId = "equipment";
        String faceId = "handsomeFace";
        MFA.AuthenticationStatus status = mfa.login(username,password,deviceId,faceId);
        assertEquals(MFA.AuthenticationStatus.TRIPLE, status);
    }

    /*
     * respondToPushNotification equivalencee partitioning
     */

    @Test(expected = NoSuchUserException.class)
    public void respondToPushNotification_EC1() throws Throwable{
        String username = "abcc";
        String deviceID = "device";
        mfa.respondToPushNotification(username,deviceID);
    }

    @Test(expected = NoSuchUserException.class)
    public void respondToPushNotification_EC2() throws Throwable{
        String username = "abcd";
        String deviceID = "device";
        MFA.AuthenticationStatus status = mfa.respondToPushNotification(username,deviceID);
        assertEquals(MFA.AuthenticationStatus.NONE, status);
        
    }

    @Test(expected = IncorrectDeviceIDException.class)
    public void respondToPushNotification_EC3() throws Throwable{
        String username = "abcd";
        String deviceID = "device";
        MFA.AuthenticationStatus status = mfa.respondToPushNotification(username,deviceID);
        assertEquals(MFA.AuthenticationStatus.SINGLE, status);
        
    }
    
    @Test
    public void respondToPushNotification_EC4() throws Throwable{
        String username = "abcd";
        String deviceID = "equipment";
        MFA.AuthenticationStatus status = mfa.respondToPushNotification(username,deviceID);
        assertEquals(MFA.AuthenticationStatus.DOUBLE, status);
        
    }

    /*
     * faceRecognised equivalence partioning
     */
    @Test(expected = NoSuchUserException.class)
    public void faceRegonised_EC1() throws Throwable{
        String username = "abcc";
        String deviceID = "equipment";
        String facialId = "face";
        mfa.faceRegonised(username,deviceID,facialId);
    }

    @Test
    public void faceRegonised_EC2() throws Throwable{
        String username = "abcd";
        String deviceID = "device";
        String facialId = "face";
        MFA.AuthenticationStatus status = mfa.faceRegonised(username,deviceID,facialId);
        assertEquals(MFA.AuthenticationStatus.NONE, status);
    }
    
    @Test(expected = IncorrectDeviceIDException.class)
    public void faceRegonised_EC3() throws Throwable{
        String username = "abcd";
        String deviceID = "device";
        String facialId = "face";
        MFA.AuthenticationStatus status = mfa.faceRegonised(username,deviceID,facialId);
        assertEquals(MFA.AuthenticationStatus.SINGLE, status);
    }

    @Test(expected = IncorrectDeviceIDException.class)
    public void faceRegonised_EC4() throws Throwable{
        String username = "abcd";
        String deviceID = "equipment";
        String facialId = "face";
        MFA.AuthenticationStatus status = mfa.faceRegonised(username,deviceID,facialId);
        assertEquals(MFA.AuthenticationStatus.SINGLE, status);
    }

    @Test(expected = FaceMismatchException.class)
    public void faceRegonised_EC5() throws Throwable{
        String username = "abcd";
        String deviceID = "equipment";
        String facialId = "face";
        MFA.AuthenticationStatus status = mfa.faceRegonised(username,deviceID,facialId);
        assertEquals(MFA.AuthenticationStatus.DOUBLE, status);
    }

    @Test
    public void faceRegonised_EC6() throws Throwable{
        String username = "abcd";
        String deviceID = "equipment";
        String facialId = "handsomeFace";
        MFA.AuthenticationStatus status = mfa.faceRegonised(username,deviceID,facialId);
        assertEquals(MFA.AuthenticationStatus.TRIPLE, status);
    }
    /*
     * getData equivalence partioning
     */

    @Test(expected = NoSuchUserException.class)
    public void getData_EC1() throws Throwable{
        String username = "abcc";
        Integer index = 0;
        mfa.getData(username,index);
        
    }

    @Test(expected = UnauthenticatedUserException.class)
    public void getData_EC2() throws Throwable{
        String username = "abcd";
        Integer index = 0;
        mfa.getData(username,index);
        assertFalse(mfa.isAuthenticated(username));
    }

    @Test
    public void getData_EC3() throws Throwable{
        String username = "aaaa";
        Integer index = -1;
        List<Integer> data = Arrays.asList(1,2,3,4,5);
        mfa.register(username, "1234abc~", null,null);
        mfa.login(username, "1234abc~");
        mfa.addData(username, data);
        mfa.getData(username,index);
    }

    @Test
    public void getData_EC4() throws Throwable{
        String username = "aaaa";
        Integer index = 2;
        List<Integer> data = Arrays.asList(1,2,3,4,5);
        mfa.register(username, "1234abc~", null,null);
        mfa.login(username, "1234abc~");
        mfa.addData(username, data);
        List<Integer> datas = mfa.getData(username,index);
        assertEquals(data, datas);
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void getData_EC5() throws Throwable{
        String username = "aaaa";
        Integer index = 10;
        List<Integer> data = Arrays.asList(1,2,3,4,5);
        mfa.register(username, "1234abc~", null,null);
        mfa.login(username, "1234abc~");
        mfa.addData(username, data);
        mfa.getData(username,index);
    }

}
