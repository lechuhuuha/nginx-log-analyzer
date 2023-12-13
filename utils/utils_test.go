package utils

import (
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestQuickSortLargeArray(t *testing.T) {
	const size = 1000000

	// Generate a large unsorted array
	unsortedArray := generateRandomArray(size)

	// Sort the array
	sortedArray := quickSortStart(unsortedArray)

	// Verify that the array is sorted
	if !isSorted(sortedArray) {
		t.Error("Array is not sorted.")
	}

	// Verify that the sorted array is a permutation of the original array
	if !reflect.DeepEqual(sortedArray, sortAndCopy(unsortedArray)) {
		t.Error("Sorted array is not a permutation of the original array.")
	}
}

func generateRandomArray(size int) []int {
	// Seed the random number generator to ensure different results on each run
	rand.Seed(time.Now().UnixNano())

	// Generate a slice with random values
	randomArray := make([]int, size)
	for i := 0; i < size; i++ {
		randomArray[i] = rand.Intn(1000000) // Adjust the upper limit as needed
	}

	return randomArray
}

func isSorted(arr []int) bool {
	for i := 1; i < len(arr); i++ {
		if arr[i-1] > arr[i] {
			return false
		}
	}
	return true
}

func sortAndCopy(arr []int) []int {
	// Create a copy of the array and sort it using a standard sorting algorithm
	// This is used to compare with the result of your QuickSort function
	arrCopy := make([]int, len(arr))
	copy(arrCopy, arr)
	// Using Go's built-in sort function for comparison
	sortSlice(arrCopy)
	return arrCopy
}

func sortSlice(arr []int) {
	// Using Go's built-in sort function
	sort.Slice(arr, func(i, j int) bool {
		return arr[i] < arr[j]
	})
}
