
// Description: Java 25 in-memory RAM DbIO implementation for SecDevice.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecDeviceTable in-memory RAM DbIO implementation
 *	for SecDevice.
 */
public class CFSecRamSecDeviceTable
	implements ICFSecSecDeviceTable
{
	private ICFSecSchema schema;
	private Map< CFSecSecDevicePKey,
				CFSecSecDeviceBuff > dictByPKey
		= new HashMap< CFSecSecDevicePKey,
				CFSecSecDeviceBuff >();
	private Map< CFSecSecDeviceByNameIdxKey,
			CFSecSecDeviceBuff > dictByNameIdx
		= new HashMap< CFSecSecDeviceByNameIdxKey,
			CFSecSecDeviceBuff >();
	private Map< CFSecSecDeviceByUserIdxKey,
				Map< CFSecSecDevicePKey,
					CFSecSecDeviceBuff >> dictByUserIdx
		= new HashMap< CFSecSecDeviceByUserIdxKey,
				Map< CFSecSecDevicePKey,
					CFSecSecDeviceBuff >>();

	public CFSecRamSecDeviceTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecDevice( CFSecAuthorization Authorization,
		CFSecSecDeviceBuff Buff )
	{
		final String S_ProcName = "createSecDevice";
		CFSecSecDevicePKey pkey = schema.getFactorySecDevice().newPKey();
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		pkey.setRequiredDevName( Buff.getRequiredDevName() );
		Buff.setRequiredSecUserId( pkey.getRequiredSecUserId() );
		Buff.setRequiredDevName( pkey.getRequiredDevName() );
		CFSecSecDeviceByNameIdxKey keyNameIdx = schema.getFactorySecDevice().newNameIdxKey();
		keyNameIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keyNameIdx.setRequiredDevName( Buff.getRequiredDevName() );

		CFSecSecDeviceByUserIdxKey keyUserIdx = schema.getFactorySecDevice().newUserIdxKey();
		keyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecDeviceNameIdx",
				keyNameIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecUser().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecUserId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"SecDeviceSecUser",
						"SecUser",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByNameIdx.put( keyNameIdx, Buff );

		Map< CFSecSecDevicePKey, CFSecSecDeviceBuff > subdictUserIdx;
		if( dictByUserIdx.containsKey( keyUserIdx ) ) {
			subdictUserIdx = dictByUserIdx.get( keyUserIdx );
		}
		else {
			subdictUserIdx = new HashMap< CFSecSecDevicePKey, CFSecSecDeviceBuff >();
			dictByUserIdx.put( keyUserIdx, subdictUserIdx );
		}
		subdictUserIdx.put( pkey, Buff );

	}

	public CFSecSecDeviceBuff readDerived( CFSecAuthorization Authorization,
		CFSecSecDevicePKey PKey )
	{
		final String S_ProcName = "CFSecRamSecDevice.readDerived";
		CFSecSecDevicePKey key = schema.getFactorySecDevice().newPKey();
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		key.setRequiredDevName( PKey.getRequiredDevName() );
		CFSecSecDeviceBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecDeviceBuff lockDerived( CFSecAuthorization Authorization,
		CFSecSecDevicePKey PKey )
	{
		final String S_ProcName = "CFSecRamSecDevice.readDerived";
		CFSecSecDevicePKey key = schema.getFactorySecDevice().newPKey();
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		key.setRequiredDevName( PKey.getRequiredDevName() );
		CFSecSecDeviceBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecDeviceBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecDevice.readAllDerived";
		CFSecSecDeviceBuff[] retList = new CFSecSecDeviceBuff[ dictByPKey.values().size() ];
		Iterator< CFSecSecDeviceBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecSecDeviceBuff readDerivedByNameIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String DevName )
	{
		final String S_ProcName = "CFSecRamSecDevice.readDerivedByNameIdx";
		CFSecSecDeviceByNameIdxKey key = schema.getFactorySecDevice().newNameIdxKey();
		key.setRequiredSecUserId( SecUserId );
		key.setRequiredDevName( DevName );

		CFSecSecDeviceBuff buff;
		if( dictByNameIdx.containsKey( key ) ) {
			buff = dictByNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecDeviceBuff[] readDerivedByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecDevice.readDerivedByUserIdx";
		CFSecSecDeviceByUserIdxKey key = schema.getFactorySecDevice().newUserIdxKey();
		key.setRequiredSecUserId( SecUserId );

		CFSecSecDeviceBuff[] recArray;
		if( dictByUserIdx.containsKey( key ) ) {
			Map< CFSecSecDevicePKey, CFSecSecDeviceBuff > subdictUserIdx
				= dictByUserIdx.get( key );
			recArray = new CFSecSecDeviceBuff[ subdictUserIdx.size() ];
			Iterator< CFSecSecDeviceBuff > iter = subdictUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecDevicePKey, CFSecSecDeviceBuff > subdictUserIdx
				= new HashMap< CFSecSecDevicePKey, CFSecSecDeviceBuff >();
			dictByUserIdx.put( key, subdictUserIdx );
			recArray = new CFSecSecDeviceBuff[0];
		}
		return( recArray );
	}

	public CFSecSecDeviceBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String DevName )
	{
		final String S_ProcName = "CFSecRamSecDevice.readDerivedByIdIdx() ";
		CFSecSecDevicePKey key = schema.getFactorySecDevice().newPKey();
		key.setRequiredSecUserId( SecUserId );
		key.setRequiredDevName( DevName );

		CFSecSecDeviceBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecDeviceBuff readBuff( CFSecAuthorization Authorization,
		CFSecSecDevicePKey PKey )
	{
		final String S_ProcName = "CFSecRamSecDevice.readBuff";
		CFSecSecDeviceBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00a" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecDeviceBuff lockBuff( CFSecAuthorization Authorization,
		CFSecSecDevicePKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecSecDeviceBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00a" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecDeviceBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecDevice.readAllBuff";
		CFSecSecDeviceBuff buff;
		ArrayList<CFSecSecDeviceBuff> filteredList = new ArrayList<CFSecSecDeviceBuff>();
		CFSecSecDeviceBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00a" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecSecDeviceBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific SecDevice buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecDevice instances in the database accessible for the Authorization.
	 */
	public CFSecSecDeviceBuff[] pageAllBuff( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecUserId,
		String priorDevName )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecSecDeviceBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String DevName )
	{
		final String S_ProcName = "CFSecRamSecDevice.readBuffByIdIdx() ";
		CFSecSecDeviceBuff buff = readDerivedByIdIdx( Authorization,
			SecUserId,
			DevName );
		if( ( buff != null ) && buff.getClassCode().equals( "a00a" ) ) {
			return( (CFSecSecDeviceBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecDeviceBuff readBuffByNameIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String DevName )
	{
		final String S_ProcName = "CFSecRamSecDevice.readBuffByNameIdx() ";
		CFSecSecDeviceBuff buff = readDerivedByNameIdx( Authorization,
			SecUserId,
			DevName );
		if( ( buff != null ) && buff.getClassCode().equals( "a00a" ) ) {
			return( (CFSecSecDeviceBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecDeviceBuff[] readBuffByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecDevice.readBuffByUserIdx() ";
		CFSecSecDeviceBuff buff;
		ArrayList<CFSecSecDeviceBuff> filteredList = new ArrayList<CFSecSecDeviceBuff>();
		CFSecSecDeviceBuff[] buffList = readDerivedByUserIdx( Authorization,
			SecUserId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00a" ) ) {
				filteredList.add( (CFSecSecDeviceBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecDeviceBuff[0] ) );
	}

	/**
	 *	Read a page array of the specific SecDevice buffer instances identified by the duplicate key UserIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The SecDevice key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecDeviceBuff[] pageBuffByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		CFLibDbKeyHash256 priorSecUserId,
		String priorDevName )
	{
		final String S_ProcName = "pageBuffByUserIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateSecDevice( CFSecAuthorization Authorization,
		CFSecSecDeviceBuff Buff )
	{
		CFSecSecDevicePKey pkey = schema.getFactorySecDevice().newPKey();
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		pkey.setRequiredDevName( Buff.getRequiredDevName() );
		CFSecSecDeviceBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecDevice",
				"Existing record not found",
				"SecDevice",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecDevice",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecSecDeviceByNameIdxKey existingKeyNameIdx = schema.getFactorySecDevice().newNameIdxKey();
		existingKeyNameIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeyNameIdx.setRequiredDevName( existing.getRequiredDevName() );

		CFSecSecDeviceByNameIdxKey newKeyNameIdx = schema.getFactorySecDevice().newNameIdxKey();
		newKeyNameIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeyNameIdx.setRequiredDevName( Buff.getRequiredDevName() );

		CFSecSecDeviceByUserIdxKey existingKeyUserIdx = schema.getFactorySecDevice().newUserIdxKey();
		existingKeyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecSecDeviceByUserIdxKey newKeyUserIdx = schema.getFactorySecDevice().newUserIdxKey();
		newKeyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Check unique indexes

		if( ! existingKeyNameIdx.equals( newKeyNameIdx ) ) {
			if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecDevice",
					"SecDeviceNameIdx",
					newKeyNameIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecUser().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecUserId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecDevice",
						"Container",
						"SecDeviceSecUser",
						"SecUser",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecSecDevicePKey, CFSecSecDeviceBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByNameIdx.remove( existingKeyNameIdx );
		dictByNameIdx.put( newKeyNameIdx, Buff );

		subdict = dictByUserIdx.get( existingKeyUserIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByUserIdx.containsKey( newKeyUserIdx ) ) {
			subdict = dictByUserIdx.get( newKeyUserIdx );
		}
		else {
			subdict = new HashMap< CFSecSecDevicePKey, CFSecSecDeviceBuff >();
			dictByUserIdx.put( newKeyUserIdx, subdict );
		}
		subdict.put( pkey, Buff );

	}

	public void deleteSecDevice( CFSecAuthorization Authorization,
		CFSecSecDeviceBuff Buff )
	{
		final String S_ProcName = "CFSecRamSecDeviceTable.deleteSecDevice() ";
		String classCode;
		CFSecSecDevicePKey pkey = schema.getFactorySecDevice().newPKey();
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		pkey.setRequiredDevName( Buff.getRequiredDevName() );
		CFSecSecDeviceBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecDevice",
				pkey );
		}
		CFSecSecDeviceByNameIdxKey keyNameIdx = schema.getFactorySecDevice().newNameIdxKey();
		keyNameIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keyNameIdx.setRequiredDevName( existing.getRequiredDevName() );

		CFSecSecDeviceByUserIdxKey keyUserIdx = schema.getFactorySecDevice().newUserIdxKey();
		keyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecSecDevicePKey, CFSecSecDeviceBuff > subdict;

		dictByPKey.remove( pkey );

		dictByNameIdx.remove( keyNameIdx );

		subdict = dictByUserIdx.get( keyUserIdx );
		subdict.remove( pkey );

	}
	public void deleteSecDeviceByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		String argDevName )
	{
		CFSecSecDevicePKey key = schema.getFactorySecDevice().newPKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setRequiredDevName( argDevName );
		deleteSecDeviceByIdIdx( Authorization, key );
	}

	public void deleteSecDeviceByIdIdx( CFSecAuthorization Authorization,
		CFSecSecDevicePKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecSecDeviceBuff cur;
		LinkedList<CFSecSecDeviceBuff> matchSet = new LinkedList<CFSecSecDeviceBuff>();
		Iterator<CFSecSecDeviceBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecDeviceBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecDevice().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId(),
				cur.getRequiredDevName() );
			deleteSecDevice( Authorization, cur );
		}
	}

	public void deleteSecDeviceByNameIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		String argDevName )
	{
		CFSecSecDeviceByNameIdxKey key = schema.getFactorySecDevice().newNameIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setRequiredDevName( argDevName );
		deleteSecDeviceByNameIdx( Authorization, key );
	}

	public void deleteSecDeviceByNameIdx( CFSecAuthorization Authorization,
		CFSecSecDeviceByNameIdxKey argKey )
	{
		CFSecSecDeviceBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecDeviceBuff> matchSet = new LinkedList<CFSecSecDeviceBuff>();
		Iterator<CFSecSecDeviceBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecDeviceBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecDevice().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId(),
				cur.getRequiredDevName() );
			deleteSecDevice( Authorization, cur );
		}
	}

	public void deleteSecDeviceByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecSecDeviceByUserIdxKey key = schema.getFactorySecDevice().newUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecDeviceByUserIdx( Authorization, key );
	}

	public void deleteSecDeviceByUserIdx( CFSecAuthorization Authorization,
		CFSecSecDeviceByUserIdxKey argKey )
	{
		CFSecSecDeviceBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecDeviceBuff> matchSet = new LinkedList<CFSecSecDeviceBuff>();
		Iterator<CFSecSecDeviceBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecDeviceBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecDevice().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId(),
				cur.getRequiredDevName() );
			deleteSecDevice( Authorization, cur );
		}
	}
}
