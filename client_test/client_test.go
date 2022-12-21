package client_test

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports. Normally, you will want to avoid underscore imports
	// unless you know exactly what you are doing. You can read more about
	// underscore imports here: https://golangdocs.com/blank-identifier-in-golang
	_ "encoding/hex"
	"errors"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect(). You can read more
	// about dot imports here:
	// https://stackoverflow.com/questions/6478962/what-does-the-dot-or-period-in-a-go-import-statement-do
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	// The client implementation is intentionally defined in a different package.
	// This forces us to follow best practice and write tests that only rely on
	// client API that is exported from the client package, and avoid relying on
	// implementation details private to the client package.
	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	// We are using 2 libraries to help us write readable and maintainable tests:
	//
	// (1) Ginkgo, a Behavior Driven Development (BDD) testing framework that
	//             makes it easy to write expressive specs that describe the
	//             behavior of your code in an organized manner; and
	//
	// (2) Gomega, an assertion/matcher library that allows us to write individual
	//             assertion statements in tests that read more like natural
	//             language. For example "Expect(ACTUAL).To(Equal(EXPECTED))".
	//
	// In the Ginko framework, a test case signals failure by calling Ginkgo’s
	// Fail(description string) function. However, we are using the Gomega library
	// to execute our assertion statements. When a Gomega assertion fails, Gomega
	// calls a GomegaFailHandler, which is a function that must be provided using
	// gomega.RegisterFailHandler(). Here, we pass Ginko's Fail() function to
	// Gomega so that Gomega can report failed assertions to the Ginko test
	// framework, which can take the appropriate action when a test fails.
	//
	// This is the sole connection point between Ginkgo and Gomega.
	RegisterFailHandler(Fail)

	RunSpecs(t, "Client Tests")
}

func getDatastoreKeys()(map[userlib.UUID]bool){
	dsMap := userlib.DatastoreGetMap()
	keys := make(map[userlib.UUID]bool)
	for k,_ := range dsMap{
		keys[k] = true
	}
	return keys
}

func difference(before map[userlib.UUID]bool, after map[userlib.UUID]bool )([]userlib.UUID){
	diff := make([]userlib.UUID,0)
	for k,_ := range after{
		_, ok := before[k]
		if !ok{diff = append(diff,k)}
	}
	return diff
}

// ================================================
// Here are some optional global variables that can be used throughout the test
// suite to make the tests more readable and maintainable than defining these
// values in each test. You can add more variables here if you want and think
// they will help keep your code clean!
// ================================================
const someFilename = "file1.txt"
const someOtherFilename = "file2.txt"
const nonExistentFilename = "thisFileDoesNotExist.txt"

const aliceUsername = "Alice"
const alicePassword = "AlicePassword"
const bobUsername = "Bob"
const bobPassword = "BobPassword"
const nilufarUsername = "Nilufar"
const nilufarPassword = "NilufarPassword"
const olgaUsername = "Olga"
const olgaPassword = "OlgaPassword"
const marcoUsername = "Marco"
const marcoPassword = "MarcoPassword"

const nonExistentUsername = "NonExistentUser"

var alice *client.User
var bob *client.User
var nilufar *client.User
var olga *client.User
var marco *client.User

var someFileContent []byte
var someShortFileContent []byte
var someLongFileContent []byte

// ================================================
// The top level Describe() contains all tests in
// this test suite in nested Describe() blocks.
// ================================================

var _ = Describe("Client Tests", func() {
	BeforeEach(func() {
		// This top-level BeforeEach will be run before each test.
		//
		// Resets the state of Datastore and Keystore so that tests do not
		// interfere with each other.
		userlib.DatastoreClear()
		userlib.KeystoreClear()

		userlib.SymbolicDebug = false
		userlib.SymbolicVerbose = false
	})

	BeforeEach(func() {
		// This top-level BeforeEach will be run before each test.
		//
		// Byte slices cannot be constant, so this BeforeEach resets the content of
		// each global variable to a predefined value, which allows tests to rely on
		// the expected value of these variables.
		someShortFileContent = []byte("some short file content")
		someFileContent = someShortFileContent
		someLongFileContent = []byte("some LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file content")
	})

	Describe("Creating users", func() {
		It("should not error when creating a new user", func() {
			_, err := client.InitUser("Alice", "password")
			Expect(err).To(BeNil(), "Failed to initialized user Alice.")
		})

		It("should  error when creating a new user with empty username", func() {
			_, err := client.InitUser("", "password")
			Expect(err).ToNot(BeNil(), "Didn't error with empty username")
		})

		It("should error if a username is already taken by another user", func() {
			client.InitUser("Alice", "first")
			_, err := client.InitUser("Alice", "second")
			Expect(err).ToNot(BeNil(), "Didn't error when trying same username")
		})

		It("should error if a user does not exist with that username", func() {
			_, err := client.GetUser("Alice", "neverInited")
			Expect(err).ToNot(BeNil(), "Didn't error when checking for nonexistent username")
		})

		It("should error if invalid credentials are given for a user", func() {
			client.InitUser("Alice", "first")
			_, err := client.GetUser("Alice", "second")
			Expect(err).ToNot(BeNil(), "Didn't error when given invalid credentials")
		})

		It("should error if userStruct has been deleted with", func() {
			client.InitUser("Alice", "first")
			userlib.DatastoreClear()
			_, err := client.GetUser("Alice", "first")
			Expect(err).ToNot(BeNil(), "Didn't error when user struct was maliciously deleted")
		})

		It("should error when trying to init user with the same username after malicious tampering", func() {
			uploadedContent := []byte("This is a test")
			byt := uploadedContent[5]
			before :=getDatastoreKeys()
			client.InitUser("Alice", "first")
			after := getDatastoreKeys()
			diff := difference(before,after)
			mp := userlib.DatastoreGetMap()
			for _,k := range diff{
				get,ok := userlib.DatastoreGet(k)
				if ok {
					get[len(get)-1] = byt
					get[len(get)-2] = byt
				}
				mp[k] = get
			}

			_, err := client.InitUser("Alice", "first")
			Expect(err).ToNot(BeNil(), "Was able to init user with same username after malicious tampering")
		})



		It("should error when trying to get usr after malicious tampering", func() {
			uploadedContent := []byte("This is a test")
			byt := uploadedContent[5]
			before :=getDatastoreKeys()
			client.InitUser("Alice", "first")
			after := getDatastoreKeys()
			diff := difference(before,after)
			mp := userlib.DatastoreGetMap()
			for _,k := range diff{
				get,ok := userlib.DatastoreGet(k)
				if ok {
					get[len(get)-1] = byt
					get[len(get)-2] = byt
				}
				mp[k] = get
			}

			_, err := client.GetUser("Alice", "first")
			Expect(err).ToNot(BeNil(), "Was able to get user after malicious tampering")
		})

		// TODO: you probably want more test cases about creating users here
	})

	Describe("Single user storage", func() {
		var alice *client.User
		BeforeEach(func() {
			// This BeforeEach will run before each test in this Describe block.
			alice, _ = client.InitUser("Alice", "some password")
		})

		It("should upload content without erroring", func() {
			content := []byte("This is a test")
			err := alice.StoreFile("file1", content)
			Expect(err).To(BeNil(), "Failed to upload content to a file", err)
		})


		It("should error when trying to loadFile after editting file", func() {
			uploadedContent := []byte("This is a test")
			LongFileContent := []byte("some LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file content")
			byt := uploadedContent[5]
			before := getDatastoreKeys()
			err := alice.StoreFile(someFilename,LongFileContent)
			after := getDatastoreKeys()
			diff := difference(before,after)
			mp := userlib.DatastoreGetMap()
			maxLen := 0
			var maxKey userlib.UUID
			for _,k := range diff{
				get,ok := userlib.DatastoreGet(k)
				if ok && len(get) > maxLen{
					maxLen = len(get)
					maxKey = k
				}
			}
			ge,ok := userlib.DatastoreGet(maxKey)
			if ok {
				ge[len(ge)-1] = byt
				ge[len(ge)-2] = byt
			}
			mp[maxKey] = ge
			_,err = alice.LoadFile(someFilename)
			Expect(err).ToNot(BeNil(), "Was able to loadFile after editting file")
		})

		It("should error when trying to loadFile after deleting file", func() {
			LongFileContent := []byte("some LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file content")
			before := getDatastoreKeys()
			err := alice.StoreFile(someFilename,LongFileContent)
			after := getDatastoreKeys()
			diff := difference(before,after)
			maxLen := 0
			var maxKey userlib.UUID
			for _,k := range diff{
				get,ok := userlib.DatastoreGet(k)
				if ok && len(get) > maxLen{
					maxLen = len(get)
					maxKey = k
				}
			}
			userlib.DatastoreDelete(maxKey)

			_,err = alice.LoadFile(someFilename)
			Expect(err).ToNot(BeNil(), "Was able to loadFile after deleting file")
		})

		It("should download the expected content that was previously uploaded", func() {
			uploadedContent := []byte("This is a test")
			alice.StoreFile(someFilename, uploadedContent)
			downloadedContent, err := alice.LoadFile(someFilename)
			Expect(err).To(BeNil(), "Storefile didn't error when userstruct was deleted", err)
			Expect(downloadedContent).To(BeEquivalentTo(uploadedContent),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent)
		})

		It("should download the expected content that was previously uploaded and appended", func() {
			totalContent := []byte("This is a test Or is it? Dun Dun")
			uploadedContent := []byte("This is a test")
			appendContent := []byte(" Or is it? Dun Dun")
			alice.StoreFile(someFilename, uploadedContent)
			downloadedContent, _ := alice.LoadFile(someFilename)
			Expect(downloadedContent).To(BeEquivalentTo(uploadedContent),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent)

			alice.AppendToFile(someFilename, appendContent)
			downloadedContent, _ = alice.LoadFile(someFilename)
			Expect(downloadedContent).To(BeEquivalentTo(totalContent),
				"Downloaded content is not the same as uploaded and appended content",
				downloadedContent,
				totalContent)
		})

		It("should download the empty byte array that was previously uploaded", func() {
			uploadedContent := make([]byte,0)
			alice.StoreFile(someFilename, uploadedContent)
			downloadedContent, _ := alice.LoadFile(someFilename)
			Expect(downloadedContent).To(BeEquivalentTo(uploadedContent),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent)
		})



		It("should error when trying to download a file that does not exist", func() {
			_, err := alice.LoadFile(nonExistentFilename)
			Expect(err).ToNot(BeNil(), "Was able to load a non-existent file without error.")
		})


		It("should error when trying to download a file that was maliciously deleted", func() {
			uploadedContent := []byte("This is a test")
			before :=getDatastoreKeys()
			alice.StoreFile(someFilename,uploadedContent)
			after := getDatastoreKeys()
			diff := difference(before,after)
			for _,k := range diff{
				userlib.DatastoreDelete(k)
			}
			_, err := alice.LoadFile(someFilename)
			Expect(err).ToNot(BeNil(), "Was able to load deleted file without error.")
		})

		It("should error when trying to download a file that was maliciously editted", func() {
			uploadedContent := []byte("This is a test")
			byt := uploadedContent[5]
			before :=getDatastoreKeys()
			alice.StoreFile(someFilename,uploadedContent)
			after := getDatastoreKeys()
			diff := difference(before,after)
			mp := userlib.DatastoreGetMap()
			for _,k := range diff{
				get,ok := userlib.DatastoreGet(k)
				if ok {
					get[len(get)-1] = byt
					get[len(get)-2] = byt
				}
				mp[k] = get
			}

			_, err := alice.LoadFile(someFilename)
			Expect(err).ToNot(BeNil(), "Was able to load maliciously editted file without error.")
		})

		It("should error when trying to download a file that does not exist", func() {
			uploadedContent := []byte("This is a test")
			alice.StoreFile(someFilename,uploadedContent)
			userlib.DatastoreClear()
			_, err := alice.LoadFile(someFilename)
			Expect(err).ToNot(BeNil(), "Was able to load deleted file without error.")
		})

		It("should error when appending to nonexistent filename", func() {
			uploadedContent := []byte("This is a test")
			alice.StoreFile(someFilename, uploadedContent)
			downloadedContent, _ := alice.LoadFile(someFilename)
			Expect(downloadedContent).To(BeEquivalentTo(uploadedContent),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent)

			err := alice.AppendToFile(nonExistentFilename, []byte("this aint appendin"))
			Expect(err).ToNot(BeNil(), "Was able to append to nonexistent filename without error.")
		})

		It("should error when trying to download a file that was maliciously editted", func() {
			uploadedContent := []byte("This is a test")
			byt := uploadedContent[5]
			before :=getDatastoreKeys()
			alice.StoreFile(someFilename,uploadedContent)
			after := getDatastoreKeys()
			diff := difference(before,after)
			mp := userlib.DatastoreGetMap()
			downloadedContent, _ := alice.LoadFile(someFilename)
			Expect(downloadedContent).To(BeEquivalentTo(uploadedContent),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent)
			for _,k := range diff{
				get,ok := userlib.DatastoreGet(k)
				if ok {
					get[len(get)-1] = byt
					get[len(get)-2] = byt
				}
				mp[k] = get
			}

			err := alice.AppendToFile(someFilename, []byte("aint appendin"))
			Expect(err).ToNot(BeNil(), "Was able to load maliciously editted file without error.")
		})
		// TODO: you probably want more test cases for store/load/append with a
		// 			 single user here
	})

	Describe("Sharing files", func() {

		BeforeEach(func() {
			// Initialize each user to ensure the variable has the expected value for
			// the tests in this Describe() block.
			alice, _ = client.InitUser(aliceUsername, alicePassword)
			bob, _ = client.InitUser(bobUsername, bobPassword)
			nilufar, _ = client.InitUser(nilufarUsername, nilufarPassword)
			olga, _ = client.InitUser(olgaUsername, olgaPassword)
			marco, _ = client.InitUser(marcoUsername, marcoPassword)
		})

		It("should share a file without erroring", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")
		})

		It("user sessions appending", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			alice_laptoP,_ := client.GetUser(aliceUsername,alicePassword)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")

			downloadedContent,err = alice_laptoP.LoadFile(someFilename)
			Expect(err).To(BeNil(), "Alice's laptop could not load the file that Alice made.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Alice's laptop downloaded was not the same as what Alice uploaded.")

			alice_laptoP.AppendToFile(someFilename,[]byte("wtf"))

			downloadedContent,err = alice.LoadFile(someFilename)
			Expect(err).To(BeNil(), "Alice  could not load the file that Alice's laptop appended")
			Expect(downloadedContent).To(BeEquivalentTo([]byte("some short file contentwtf")),
				"The file contents that Alice downloaded was not the same as what Alice's laptop appended")

			alice_laptoP.StoreFile(someFilename,[]byte("whaaat"))
			downloadedContent,err = alice.LoadFile(someFilename)
			Expect(err).To(BeNil(), "Alice  could not load the file that Alice's laptop overwrote")
			Expect(downloadedContent).To(BeEquivalentTo([]byte("whaaat")),
				"The file contents that Alice downloaded was not the same as what Alice's laptop overwrote")
		})

		It("acceptInvitation should error if using a preexisting filename", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			bob.StoreFile(someOtherFilename,[]byte("I am reserving this filename"))
			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).ToNot(BeNil(), "Bob accepted invitation using preexisting filename")
		})

		It("acceptInvitation should error if invitationPtr has been tampered with", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			mp := userlib.DatastoreGetMap()
			mp[shareFileInfoPtr] = []byte("gotteeem")
			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).ToNot(BeNil(), "Bob accepted invitation despite invitationPtr being tampered with")
		})

		It("acceptInvitation should error if called after invitation revoked", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			alice.RevokeAccess(someFilename,bobUsername)
			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).ToNot(BeNil(), "Bob accepted invitation despite invitation being revoked")
		})

		It("should err when sharing a file with nonexistent filename", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			_, err := alice.CreateInvitation(nonExistentFilename, bobUsername)
			Expect(err).ToNot(BeNil(), "Created invitation for nonExistent filename without error")

		})



		It("should error when trying to create invitation after malicious tampering", func() {
			uploadedContent := []byte("This is a test")
			byt := uploadedContent[5]
			before :=getDatastoreKeys()
			alice.StoreFile(someFilename,uploadedContent)
			after := getDatastoreKeys()
			diff := difference(before,after)
			mp := userlib.DatastoreGetMap()
			downloadedContent, _ := alice.LoadFile(someFilename)
			Expect(downloadedContent).To(BeEquivalentTo(uploadedContent),
				"Downloaded content is not the same as uploaded content",
				downloadedContent,
				uploadedContent)
			for _,k := range diff{
				get,ok := userlib.DatastoreGet(k)
				if ok {
					get[len(get)-1] = byt
					get[len(get)-2] = byt
				}
				mp[k] = get
			}

			_, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).ToNot(BeNil(), "Created invitation after malicious tampering without error")
		})



		// TODO: you probably want more test cases for sharing files here
		It("should revoke Bob and Nilufar's access", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")
			shareFileInfoPtr, err = bob.CreateInvitation(someOtherFilename, nilufarUsername)
			Expect(err).To(BeNil(), "Bob failed to share file with Nilufar")
			err = nilufar.AcceptInvitation(bobUsername, shareFileInfoPtr, nonExistentFilename)
			Expect(err).To(BeNil(), "Nilufar could not receive file shared by Bob")

			downloadedContent, err = nilufar.LoadFile(nonExistentFilename)
			Expect(err).To(BeNil(), "Nilufar could not load the file that Bob shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Nilufar downloaded was not the same as what Alice uploaded.")

			err = alice.RevokeAccess(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice could not revoke Bobs and consequently Nilufar's access")

			downloadedContent, err = bob.LoadFile(someOtherFilename)
			Expect(err).ToNot(BeNil(), "LoadFile should error if bob tries to access after revocation", err)

			downloadedContent, err = nilufar.LoadFile(nonExistentFilename)
			Expect(err).ToNot(BeNil(), "LoadFile should error if nilufar tries to access after revocation", err)



		})

		It("should revoke Bob and Nilufar's access", func() {
			before :=getDatastoreKeys()

			alice.StoreFile(someFilename, someShortFileContent)
			after := getDatastoreKeys()
			diff := difference(before,after)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")

			err = alice.RevokeAccess(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice could not revoke Bobs and consequently Nilufar's access")

			downloadedContent, err = bob.LoadFile(someOtherFilename)
			Expect(err).ToNot(BeNil(), "LoadFile should error if bob tries to access after revocation", err)
			err = nil

			for _,k := range diff {
				_, ok := userlib.DatastoreGet(k)
				if !ok{
					err = errors.New("can't look her")
					break
				}
			}
			Expect(err).ToNot(BeNil(), "file should be deleted from old file location", err)



		})

		It("bob accepts invitation and loads file on his laptop", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			bobLaptop,err := client.GetUser(bobUsername,bobPassword)
			Expect(err).To(BeNil(), "Bob logged in on laptop")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")

			downloadedContent, err = bobLaptop.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file shared from Alice on his laptop")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded on his laptop was not the same as what Alice uploaded.")




		})

		It("should error when nilufar tries to accept Bob's invitation with sender username  as Alic", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = nilufar.AcceptInvitation(aliceUsername,shareFileInfoPtr,"filie")
			Expect(err).ToNot(BeNil(), "Nilufar Accepted invitation shared with bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")
			shareFileInfoPtr, err = bob.CreateInvitation(someOtherFilename, nilufarUsername)
			Expect(err).To(BeNil(), "Bob failed to share file with Nilufar")
			err = nilufar.AcceptInvitation(aliceUsername, shareFileInfoPtr, nonExistentFilename)
			Expect(err).ToNot(BeNil(), "Nilufar accepted Bob's invitation with Nilufar as senderUsername")

		})
		It("should error since Alice is revoking from Nilufar who doesn't even have access", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")


			err = alice.RevokeAccess(someFilename, nilufarUsername)
			Expect(err).ToNot(BeNil(), "Alice revoked Nilufar's access despite Nilufar not having access")


		})

		It("should error since Alice cannot revoke a file she never made in her namespace", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")
			shareFileInfoPtr, err = bob.CreateInvitation(someOtherFilename, nilufarUsername)
			Expect(err).To(BeNil(), "Bob failed to share file with Nilufar")
			err = nilufar.AcceptInvitation(bobUsername, shareFileInfoPtr, nonExistentFilename)
			Expect(err).To(BeNil(), "Nilufar could not receive file shared by Bob")

			downloadedContent, err = nilufar.LoadFile(nonExistentFilename)
			Expect(err).To(BeNil(), "Nilufar could not load the file that Bob shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Nilufar downloaded was not the same as what Alice uploaded.")

			err = alice.RevokeAccess(someOtherFilename, bobUsername)
			Expect(err).ToNot(BeNil(), "Alice revoked a file she never made in her namespace")


		})

		It("should error after revoke access is called after file related stuff is tampered with", func() {
			uploadedContent := []byte("This is a test")
			byt := uploadedContent[5]
			before :=getDatastoreKeys()
			alice.StoreFile(someFilename, someShortFileContent)
			after := getDatastoreKeys()
			diff := difference(before,after)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")
			shareFileInfoPtr, err = bob.CreateInvitation(someOtherFilename, nilufarUsername)
			Expect(err).To(BeNil(), "Bob failed to share file with Nilufar")
			err = nilufar.AcceptInvitation(bobUsername, shareFileInfoPtr, nonExistentFilename)
			Expect(err).To(BeNil(), "Nilufar could not receive file shared by Bob")

			downloadedContent, err = nilufar.LoadFile(nonExistentFilename)
			Expect(err).To(BeNil(), "Nilufar could not load the file that Bob shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Nilufar downloaded was not the same as what Alice uploaded.")
			mp := userlib.DatastoreGetMap()
			for _,k := range diff{
				get,ok := userlib.DatastoreGet(k)
				if ok {
					get[len(get)-1] = byt
					get[len(get)-2] = byt
				}
				mp[k] = get
			}
			err = alice.RevokeAccess(someFilename, bobUsername)
			Expect(err).ToNot(BeNil(), "Alice could revoke despite file related stuff being tampered with")

		})

		It("should revoke Bob and Nilufar's access while maintaining Marco's", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")

			shareFileInfoPtr, err = alice.CreateInvitation(someFilename, marcoUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Marco.")
			err = marco.AcceptInvitation(aliceUsername, shareFileInfoPtr, "filename")
			Expect(err).To(BeNil(), "Marco could not receive the file that Alice shared.")

			downloadedContent, err = marco.LoadFile("filename")
			Expect(err).To(BeNil(), "Marco could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Marco downloaded was not the same as what Alice uploaded.")

			shareFileInfoPtr, err = marco.CreateInvitation("filename", olgaUsername)
			Expect(err).To(BeNil(), "Marco failed to share a file with Olga.")
			err = olga.AcceptInvitation(marcoUsername, shareFileInfoPtr, "filename")
			Expect(err).To(BeNil(), "Olga could not receive the file that Marco shared.")

			downloadedContent, err = olga.LoadFile("filename")
			Expect(err).To(BeNil(), "Olga could not load the file that Marco shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Olga downloaded was not the same as what Alice uploaded.")

			shareFileInfoPtr, err = bob.CreateInvitation(someOtherFilename, nilufarUsername)
			Expect(err).To(BeNil(), "Bob failed to share file with Nilufar")
			err = nilufar.AcceptInvitation(bobUsername, shareFileInfoPtr, nonExistentFilename)
			Expect(err).To(BeNil(), "Nilufar could not receive file shared by Bob")

			downloadedContent, err = nilufar.LoadFile(nonExistentFilename)
			Expect(err).To(BeNil(), "Nilufar could not load the file that Bob shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Nilufar downloaded was not the same as what Alice uploaded.")

			err = alice.RevokeAccess(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice could not revoke Bobs and consequently Nilufar's access, marco Test")

			downloadedContent, err = bob.LoadFile(someOtherFilename)
			Expect(err).ToNot(BeNil(), "LoadFile should error if bob tries to access after revocation", err)

			downloadedContent, err = nilufar.LoadFile(nonExistentFilename)
			Expect(err).ToNot(BeNil(), "LoadFile should error if nilufar tries to access after revocation", err)

			downloadedContent, err = marco.LoadFile("filename")
			Expect(err).To(BeNil(), "Marco could not load the file that Alice shared.x2")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Marco downloaded was not the same as what Alice uploaded.")

			downloadedContent, err = olga.LoadFile("filename")
			Expect(err).To(BeNil(), "Olga could not load the file that Marco shared. x2")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Olga downloaded was not the same as what Alice uploaded.")


			err = nilufar.AcceptInvitation(bobUsername, shareFileInfoPtr, nonExistentFilename)
			Expect(err).ToNot(BeNil(), "Nilufar could accept invitation after being revoked")

			err = nilufar.AppendToFile(nonExistentFilename, []byte("whatooo"))
			Expect(err).ToNot(BeNil(), "Nilufar could append file after being revoked")

		})

		It("should revoke Bob and Nilufar's access while maintaining Marco's", func() {
			alice.StoreFile(someFilename, someShortFileContent)
			shareFileInfoPtr, err := alice.CreateInvitation(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Bob.")

			err = bob.AcceptInvitation(aliceUsername, shareFileInfoPtr, someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not receive the file that Alice shared.")

			downloadedContent, err := bob.LoadFile(someOtherFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")

			shareFileInfoPtr, err = alice.CreateInvitation(someFilename, marcoUsername)
			Expect(err).To(BeNil(), "Alice failed to share a file with Marco.")
			err = marco.AcceptInvitation(aliceUsername, shareFileInfoPtr, "filename")
			Expect(err).To(BeNil(), "Marco could not receive the file that Alice shared.")

			downloadedContent, err = marco.LoadFile("filename")
			Expect(err).To(BeNil(), "Marco could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Marco downloaded was not the same as what Alice uploaded.")

			shareFileInfoPtr, err = marco.CreateInvitation("filename", olgaUsername)
			Expect(err).To(BeNil(), "Marco failed to share a file with Olga.")
			err = olga.AcceptInvitation(marcoUsername, shareFileInfoPtr, "filename")
			Expect(err).To(BeNil(), "Olga could not receive the file that Marco shared.")

			downloadedContent, err = olga.LoadFile("filename")
			Expect(err).To(BeNil(), "Olga could not load the file that Marco shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Olga downloaded was not the same as what Alice uploaded.")

			shareFileInfoPtr, err = bob.CreateInvitation(someOtherFilename, nilufarUsername)
			Expect(err).To(BeNil(), "Bob failed to share file with Nilufar")
			err = nilufar.AcceptInvitation(bobUsername, shareFileInfoPtr, nonExistentFilename)
			Expect(err).To(BeNil(), "Nilufar could not receive file shared by Bob")

			downloadedContent, err = nilufar.LoadFile(nonExistentFilename)
			Expect(err).To(BeNil(), "Nilufar could not load the file that Bob shared.")
			Expect(downloadedContent).To(BeEquivalentTo(someShortFileContent),
				"The file contents that Nilufar downloaded was not the same as what Alice uploaded.")
			nilufar.AppendToFile(nonExistentFilename,someLongFileContent)
			bob.AppendToFile(someOtherFilename,someFileContent)
			fileContent := []byte("some short file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome short file content")

			downloadedContent, err = alice.LoadFile(someFilename)
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.")
			Expect(downloadedContent).To(BeEquivalentTo(fileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")
			err = alice.RevokeAccess(someFilename, bobUsername)
			Expect(err).To(BeNil(), "Alice could not revoke Bobs and consequently Nilufar's access, marco Test")

			err = olga.AppendToFile("filename",[]byte("wtf"))
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.x2")
			downloadedContent, err = marco.LoadFile("filename")
			Expect(err).To(BeNil(), "Bob could not load the file that Alice shared.x3")
			fileContent = []byte("some short file contentsome LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONG file contentsome short file contentwtf")
			Expect(downloadedContent).To(BeEquivalentTo(fileContent),
				"The file contents that Bob downloaded was not the same as what Alice uploaded.")

		})

		// TODO: you probably want more Describe() blocks to contain tests related to
		//       logical test groupings other than the ones suggested above
	})
})