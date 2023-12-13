package utils

func QuickSort(arr []int, low, high int) []int {
	if low < high {
		var p int
		arr, p = partition(arr, low, high)
		arr = QuickSort(arr, low, p-1)
		arr = QuickSort(arr, p+1, high)
	}
	return arr
}

func quickSortStart(arr []int) []int {
	return QuickSort(arr, 0, len(arr)-1)
}
func partition(arr []int, low, high int) ([]int, int) {
	pivot := arr[high]
	i := low
	for j := low; j < high; j++ {
		if arr[j] < pivot {
			arr[i], arr[j] = arr[j], arr[i]
			i++
		}
	}
	arr[i], arr[high] = arr[high], arr[i]
	return arr, i
}
