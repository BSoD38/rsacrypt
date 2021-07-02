const bigInt = require("big-integer");

function isPrime(number) {
    if (typeof number !== 'number') throw new TypeError('Expected input of type Number')

    if (number <= 3) return number > 1

    if (number % 2 === 0 || number % 3 === 0) return false

    const maxDivisor = Math.floor(Math.sqrt(number))
    for (let i = 5; i <= maxDivisor; i += 6) {
        // eslint-disable-next-line no-mixed-operators
        if (number % i === 0 || number % i + 2 === 0) return false
    }

    return true
}

function randomPrime(bits) {
    const min = bigInt.one.shiftLeft(bits - 1);
    const max = bigInt.one.shiftLeft(bits).prev();

    while (true) {
        let p = bigInt.randBetween(min, max);
        if (p.isProbablePrime(256)) {
            return p;
        }
    }
}

function decompose(n) {
    let factors = [];
    let divisor = bigInt(2);

    while (n.greaterOrEquals(2)) {
        if (n.mod(divisor).equals(0)) {
            factors.push(divisor);
            n = n.divide(divisor);
        } else {
            divisor = divisor.add(1);
        }
    }
    if (factors.length > 2) {
        let divisor = factors[1];
        for (const factor of factors.slice(2)) {
            divisor = divisor.multiply(factor);
        }
        factors = [factors[0], divisor];
    }
    return factors;
}

module.exports = {randomPrime, isPrime, decompose};
