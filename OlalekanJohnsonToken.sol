pragma solidity ^0.5.8;

/**
 * Math operations with safety checks
 */
contract SafeMath {

    function safeMul(uint a, uint b)internal pure returns (uint) {
        uint c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function safeDiv(uint a, uint b)internal pure returns (uint) {
        assert(b > 0);
        uint c = a / b;
        assert(a == b * c + a % b);
        return c;
    }

    function safeSub(uint a, uint b)internal pure returns (uint) {
        assert(b <= a);
        return a - b;
    }

    function safeAdd(uint a, uint b)internal pure returns (uint) {
        uint c = a + b;
        assert(c>=a && c>=b);
        return c;
    }
}


/*
 * Base Token for ERC20 compatibility
 * ERC20 interface
 * see https://github.com/ethereum/EIPs/issues/20
 */
contract ERC20 {
    string public name;
    uint8 public decimals;
    string public symbol;
    uint public totalSupply;
    function balanceOf(address who) public view returns (uint);
    function allowance(address owner, address spender) public view returns (uint);
    function transferFrom(address from, address to, uint value) public returns (bool ok);
    function approve(address spender, uint value) public returns (bool ok);
    function transfer(address to, uint value) public returns (bool ok);
    event Transfer(address indexed from, address indexed to, uint value);
    event Approval(address indexed owner, address indexed spender, uint value);
}


/*
 * Ownable
 *
 * Base contract with an owner.
 * Provides onlyOwner modifier, which prevents function from running if it is called by anyone other than the owner.
 */
contract Ownable is ERC20, SafeMath{
    /* Address of the owner */
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "You don't have permission to perform this transaction");
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner{
        require(newOwner != owner,"You cant transfer ownership to yourself");
        require(newOwner != address(0), "You can't transfer ownership to empty address");
        owner = newOwner;
    }

}

/**
 * Standard ERC20 token with Short Hand Attack and approve() race condition mitigation.
 *
 * Based on code by FirstBlood:
 * https://github.com/Firstbloodio/token/blob/master/smart_contract/FirstBloodToken.sol
 */
contract StandardToken is Ownable{

    /* Actual balances of each token holder */
    mapping(address => uint) balances;

    /* approve() allowances */
    mapping (address => mapping (address => uint)) internal allowed;
    /**
     *
     * Fix for the ERC20 short address attack
     *
     * http://vessenes.com/the-erc20-short-address-attack-explained/
     */
    modifier onlyPayloadSize(uint size) {
        if(msg.data.length < size + 4) {
        revert("Unable to perform this transaction");
        }
        _;
    }
    /**
     *
     * Transfer with ERC20 specification
     *
     * http://vessenes.com/the-erc20-short-address-attack-explained/
     */
    function transfer(address _to, uint _value)
    public
    onlyPayloadSize(2 * 32)
    returns (bool success)
    {
        require(_to != address(0),"You can't transfer to an empty address");
        if (balances[msg.sender] >= _value && _value > 0) {
            balances[msg.sender] = safeSub(balances[msg.sender], _value);
            balances[_to] = safeAdd(balances[_to], _value);
            emit Transfer(msg.sender, _to, _value);
            return true;
        }else {
            return false;
        }

    }

    function transferFrom(address _from, address _to, uint _value)
    public
    returns (bool success)
    {
        require(_to != address(0), "You can't transfer to an empty address");
        require(_value <= balances[_from],"Token owner do not have sufficient balance");
        require(_value <= allowed[_from][msg.sender],"You are not assigned sufficient token");
        uint _allowance = allowed[_from][msg.sender];
        balances[_to] = safeAdd(balances[_to], _value);
        balances[_from] = safeSub(balances[_from], _value);
        allowed[_from][msg.sender] = safeSub(_allowance, _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint _value)
    public
    returns (bool success)
    {
        require(_spender != address(0), "You can't share token with empty account");
        // To change the approve amount you first have to reduce the addresses`
        //    allowance to zero by calling `approve(_spender, 0)` if it is not
        //    already 0 to mitigate the race condition described here:
        //    https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
        //if ((_value != 0) && (allowed[msg.sender][_spender] != 0)) throw;
        require(_value == 0 || allowed[msg.sender][_spender] == 0, "Balance must be zero");
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    /**
     * approve should be called when allowed[_spender] == 0. To increment
     * allowed value is better to use this function to avoid 2 calls (and wait until
     * the first transaction is mined)
     * From MonolithDAO Token.sol
     */
    function increaseApproval(address _spender, uint _addedValue) public returns (bool) {
        allowed[msg.sender][_spender] = safeAdd(allowed[msg.sender][_spender], _addedValue);
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function decreaseApproval(address _spender, uint _subtractedValue) public returns (bool) {
        uint oldValue = allowed[msg.sender][_spender];
        if (_subtractedValue > oldValue) {
            allowed[msg.sender][_spender] = 0;
        } else {
            allowed[msg.sender][_spender] = safeSub(oldValue, _subtractedValue);
        }
        emit Approval(msg.sender, _spender, allowed[msg.sender][_spender]);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint remaining) {
        return allowed[_owner][_spender];
    }

}

/**
 * A token that can increase its supply by another contract.
 *
 * This allows uncapped crowdsale by dynamically increasing the supply when money pours in.
 * Only mint agents, contracts whitelisted by owner, can mint new tokens.
 *
 */
contract MintableToken is StandardToken {
    /** List of agents that are allowed to create new tokens */
    mapping (address => bool) private mintAgents;

    event MintingAgentChanged(address addr, bool state);
    event Mint(address indexed to, uint value);
    event Burn(address indexed from, uint value);

    constructor() public {
        setMintAgent(msg.sender, true);
    }

    /**
     * Create new tokens and allocate them to an address..
     *
     * Only callably by a crowdsale contract (mint agent).
     */
    function _mint(address receiver, uint amount) private onlyMintAgent {
        totalSupply = safeAdd(totalSupply, amount);
        balances[receiver] = safeAdd(balances[receiver], amount);

        // We can remove this after there is a standardized minting event
        emit Transfer(address(0), receiver, amount);
        emit Mint(receiver, amount);
    }

    function mint(uint amount) public onlyMintAgent {
        _mint(msg.sender, amount);
    }

    function burn(address from, uint amount)public onlyOwner{
        require(balances[from] >= amount && amount > 0, "Invalid amount");
        balances[from] = safeSub(balances[from],amount);
        totalSupply = safeSub(totalSupply, amount);
        emit Transfer(from, address(0), amount);
        emit Burn(from, amount);
    }

    function burn(uint amount)public onlyMintAgent  {
        burn(msg.sender, amount);
    }

    /**
     * Owner can allow a new address to mint new tokens.
     */
    function setMintAgent(address addr, bool state) public onlyOwner  {
        mintAgents[addr] = state;
        emit MintingAgentChanged(addr, state);
    }

    /**
     * This will check if an address can mint
     */
    modifier onlyMintAgent() {
        if(!mintAgents[msg.sender]) revert("You don't have permissions to mint token");
        _;
    }
}


contract OlalekanJohnsonToken is MintableToken {
    constructor() public{
        decimals = 18;     // Amount of decimals for display purposes
        totalSupply = safeMul(1000000, 10**18);     // Update total supply
        balances[msg.sender] = totalSupply;    // Give the creator all initial tokens
        name = "OlalekanJohnsonToken";    // Set the name for display purposes
        symbol = "OLT";    // Set the symbol for display purposes
    }
}