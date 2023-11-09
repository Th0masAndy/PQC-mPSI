def write_numbers_to_file(numbers, filename):
    with open(filename, "w") as file:
        for number in numbers:
            # 将数字转换为字符串并写入文件，每个数字后跟一个换行符
            file.write(str(number) + "\n")


# 使用例子
for i in range(1, 15):
    numbers_to_write = [0] * (8192 * 5)
    write_numbers_to_file(numbers_to_write, "input%d.txt" % i)


i = 0
numbers_to_write = [0] * (8192 * 5 * 14)
write_numbers_to_file(numbers_to_write, "input%d.txt" % i)
