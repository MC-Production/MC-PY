pi_value = 4.0
four = 4.0
denominator_value = 3.0
iterations = 50000000000000 

for i in range(0, iterations):
    if pi_value == 4: 
        pi_value = float(pi_value - float(four / denominator_value))
        print("%0.20f" % pi_value)
        denominator_value += 2

    if i % 2 == 0: 
        pi_value = float(pi_value + float(four / denominator_value))
        print("%0.20f" % pi_value)
        denominator_value = denominator_value + 2

    if i % 2 == 1: 
        pi_value = float(pi_value - float(four / denominator_value))
        print("%0.20f" % pi_value)
        denominator_value = denominator_value + 2
