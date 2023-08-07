package swen90006.mfa;

import org.junit.*;
import static org.junit.Assert.*;

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
}
